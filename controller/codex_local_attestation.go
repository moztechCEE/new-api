package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

const codexLocalAttestationVersion = "new-api.local-codex-attest.v1"

type codexLocalAttestationRequest struct {
	Nonce        string  `json:"nonce"`
	Phase        string  `json:"phase"`
	CallIDHash   string  `json:"call_id_hash"`
	InputSHA256  string  `json:"input_sha256"`
	SchemaSHA256 *string `json:"schema_sha256"`
	Model        string  `json:"model"`
	Group        string  `json:"group"`
}

type codexLocalAttestationResponse struct {
	Version       string  `json:"version"`
	ChannelID     int     `json:"channel_id"`
	Model         string  `json:"model"`
	Group         string  `json:"group"`
	Nonce         string  `json:"nonce"`
	Phase         string  `json:"phase"`
	CallIDHash    string  `json:"call_id_hash"`
	InputSHA256   string  `json:"input_sha256"`
	SchemaSHA256  *string `json:"schema_sha256"`
	RouteRevision string  `json:"route_revision"`
	IssuedAt      int64   `json:"issued_at"`
	ExpiresAt     int64   `json:"expires_at"`
	Proof         string  `json:"proof"`
}

// CodexLocalAttestationGate makes this owner-local experiment unavailable by
// default, including before dashboard authentication. It never enables raw-key
// reads or replaces the step-up proof required by the existing key endpoint.
func CodexLocalAttestationGate(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if os.Getenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED") != "true" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Next()
}

func localAttestationError(c *gin.Context, status int) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": "local_attestation_unavailable"})
}

// CreateCodexLocalAttestation proves possession of the channel's current
// credential without returning any credential material. A proof is bound to a
// caller nonce and one model invocation; it is not accepted for authentication,
// channel-key disclosure, token refresh or any other operation.
func CreateCodexLocalAttestation(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if os.Getenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED") != "true" {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	identity, ok := middleware.GetSessionAuthIdentity(c)
	_, pat := model.ParseAccessTokenSessionID(identity.SessionID)
	if !ok || pat || c.GetBool("use_access_token") || c.GetInt("role") < common.RoleRootUser || !authz.Can(identity.UserID, c.GetInt("role"), authz.ChannelSecretView) {
		localAttestationError(c, http.StatusForbidden)
		return
	}
	if err := service.ValidateStepUpIdentity(identity); err != nil {
		localAttestationError(c, http.StatusForbidden)
		return
	}
	channelID, err := strconv.Atoi(c.Param("id"))
	if err != nil || channelID <= 0 {
		localAttestationError(c, http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4097))
	if err != nil || len(body) > 4096 {
		localAttestationError(c, http.StatusBadRequest)
		return
	}
	var fields map[string]common.RawMessage
	if err := common.Unmarshal(body, &fields); err != nil || len(fields) != 7 {
		localAttestationError(c, http.StatusBadRequest)
		return
	}
	for field := range fields {
		if !slices.Contains([]string{"nonce", "phase", "call_id_hash", "input_sha256", "schema_sha256", "model", "group"}, field) {
			localAttestationError(c, http.StatusBadRequest)
			return
		}
	}
	var request codexLocalAttestationRequest
	if err := common.Unmarshal(body, &request); err != nil || !validLocalAttestationRequest(request) {
		localAttestationError(c, http.StatusBadRequest)
		return
	}
	// Deliberately bypass the routing cache: before/after proof must reflect a
	// revocation, credential refresh or route change made since inference started.
	channel, err := model.GetChannelById(channelID, true)
	if err != nil || channel.Type != constant.ChannelTypeCodex || channel.Status != common.ChannelStatusEnabled || channel.ChannelInfo.IsMultiKey || channel.ChannelInfo.MultiKeySize > 1 || !slices.Contains(channel.GetModels(), request.Model) || !slices.Contains(channel.GetGroups(), request.Group) {
		localAttestationError(c, http.StatusConflict)
		return
	}
	credentialKey, ok := localCodexCredentialProofKey(channel.Key)
	if !ok {
		localAttestationError(c, http.StatusConflict)
		return
	}
	routeRevision, err := localCodexRouteRevision(channel, credentialKey)
	if err != nil {
		localAttestationError(c, http.StatusConflict)
		return
	}
	now := time.Now().UnixMilli()
	response := codexLocalAttestationResponse{Version: codexLocalAttestationVersion, ChannelID: channelID, Model: request.Model, Group: request.Group, Nonce: request.Nonce, Phase: request.Phase, CallIDHash: request.CallIDHash, InputSHA256: request.InputSHA256, SchemaSHA256: request.SchemaSHA256, RouteRevision: routeRevision, IssuedAt: now, ExpiresAt: now + 120000}
	schemaHash := "-"
	if response.SchemaSHA256 != nil {
		schemaHash = *response.SchemaSHA256
	}
	mac := hmac.New(sha256.New, credentialKey[:])
	writeLocalAttestationParts(mac, response.Version, response.Nonce, response.Phase, response.CallIDHash, response.InputSHA256, schemaHash, response.Model, response.Group, strconv.Itoa(response.ChannelID), response.RouteRevision, strconv.FormatInt(response.IssuedAt, 10), strconv.FormatInt(response.ExpiresAt, 10))
	response.Proof = hex.EncodeToString(mac.Sum(nil))
	if err := service.ValidateStepUpIdentity(identity); err != nil {
		localAttestationError(c, http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, response)
}

func validLocalAttestationRequest(request codexLocalAttestationRequest) bool {
	return localAttestationHex(request.Nonce) && localAttestationHex(request.CallIDHash) && localAttestationHex(request.InputSHA256) && (request.SchemaSHA256 == nil || localAttestationHex(*request.SchemaSHA256)) && (request.Phase == "before" || request.Phase == "after") && localAttestationName(request.Model, 256) && localAttestationName(request.Group, 64)
}

func localAttestationHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func localAttestationName(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f || char == ',' {
			return false
		}
	}
	return true
}

func localCodexCredentialProofKey(raw string) ([32]byte, bool) {
	var credential service.CodexOAuthKey
	if len(raw) > 4*65536+4096 || common.UnmarshalJsonStr(raw, &credential) != nil || (credential.Type != "" && credential.Type != "codex") {
		return [32]byte{}, false
	}
	values := []string{credential.AccessToken, credential.IDToken, credential.RefreshToken, credential.AccountID}
	for _, value := range values {
		if value == "" || len(value) > 65536 {
			return [32]byte{}, false
		}
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("new-api.codex-credential.v1\x00"))
	writeLocalAttestationParts(digest, values...)
	var key [32]byte
	copy(key[:], digest.Sum(nil))
	return key, true
}

func writeLocalAttestationParts(digest hash.Hash, parts ...string) {
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(part))
	}
}

func localCodexRouteRevision(channel *model.Channel, credentialKey [32]byte) (string, error) {
	// Only routing configuration belongs here, not mutable usage counters or
	// last-test timings. Override values remain opaque inside the digest.
	metadata := struct {
		ID, Type, Status                                             int
		Models, Group, Other, OtherSettings                          string
		BaseURL, OpenAIOrganization, ModelMapping, StatusCodeMapping *string
		Setting, ParamOverride, HeaderOverride                       *string
		Priority                                                     *int64
		Weight                                                       *uint
		AutoBan                                                      *int
		IsMultiKey                                                   bool
		CredentialRevision                                           string
	}{
		ID: channel.Id, Type: channel.Type, Status: channel.Status,
		Models: channel.Models, Group: channel.Group, Other: channel.Other, OtherSettings: channel.OtherSettings,
		BaseURL: channel.BaseURL, OpenAIOrganization: channel.OpenAIOrganization, ModelMapping: channel.ModelMapping, StatusCodeMapping: channel.StatusCodeMapping,
		Setting: channel.Setting, ParamOverride: channel.ParamOverride, HeaderOverride: channel.HeaderOverride,
		Priority: channel.Priority, Weight: channel.Weight, AutoBan: channel.AutoBan,
		IsMultiKey: channel.ChannelInfo.IsMultiKey, CredentialRevision: hex.EncodeToString(credentialKey[:]),
	}
	encoded, err := common.Marshal(metadata)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
