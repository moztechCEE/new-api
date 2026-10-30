package controller

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// The fixture uses synthetic credentials and the normal dashboard authenticator.
func localAttestationFixture(t *testing.T) (*gin.Engine, *model.Channel, string, service.AuthIdentity) {
	t.Helper()
	user, _ := setupSecurityEnrollmentTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.Channel{}))
	require.NoError(t, model.DB.Model(user).Update("role", common.RoleRootUser).Error)
	require.NoError(t, model.PublishUserAuthCache(user.Id))
	bundle, err := service.CreateLoginSession(user.Id, "password", "127.0.0.1", "attestation-test")
	require.NoError(t, err)
	identity, err := service.ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)
	channel := &model.Channel{Type: constant.ChannelTypeCodex, Status: common.ChannelStatusEnabled, Name: "synthetic-local", Models: "gpt-6.1-sol", Group: "local-synthetic", Key: `{"access_token":"synthetic-access","id_token":"synthetic-id","refresh_token":"synthetic-refresh","account_id":"synthetic-account"}`}
	require.NoError(t, model.DB.Create(channel).Error)
	t.Setenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED", "true")
	router := gin.New()
	path := "/api/channel/:id/codex-local-attestation"
	middleware.DeclareAccessTokenPermissionRoute(http.MethodPost, path, authz.ChannelSecretView)
	router.POST(path, CodexLocalAttestationGate, middleware.RootAuth(), middleware.RequirePermission(authz.ChannelSecretView), CreateCodexLocalAttestation)
	return router, channel, bundle.AccessToken, identity
}

func localAttestationBody(t *testing.T, changes map[string]any) string {
	t.Helper()
	body := map[string]any{"nonce": strings.Repeat("a", 64), "phase": "before", "call_id_hash": strings.Repeat("b", 64), "input_sha256": strings.Repeat("c", 64), "schema_sha256": nil, "model": "gpt-6.1-sol", "group": "local-synthetic"}
	for key, value := range changes {
		body[key] = value
	}
	data, err := common.Marshal(body)
	require.NoError(t, err)
	return string(data)
}

func localAttestationRequest(router http.Handler, id int, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/channel/%d/codex-local-attestation", id), strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestCodexLocalAttestationNormalSessionAndContextBinding(t *testing.T) {
	router, channel, token, _ := localAttestationFixture(t)
	response := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, nil))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var attestation codexLocalAttestationResponse
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &attestation))
	assert.Equal(t, "new-api.local-codex-attest.v1", attestation.Version)
	assert.Equal(t, channel.Id, attestation.ChannelID)
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Nil(t, attestation.SchemaSHA256)
	assert.InDelta(t, time.Now().UnixMilli(), attestation.IssuedAt, 3000)
	assert.Equal(t, int64(120000), attestation.ExpiresAt-attestation.IssuedAt)

	// Independently encode the documented cross-language key and proof contract.
	var keyMaterial bytes.Buffer
	keyMaterial.WriteString("new-api.codex-credential.v1\x00")
	for _, value := range []string{"synthetic-access", "synthetic-id", "synthetic-refresh", "synthetic-account"} {
		require.NoError(t, binary.Write(&keyMaterial, binary.BigEndian, uint32(len(value))))
		keyMaterial.WriteString(value)
	}
	key := sha256.Sum256(keyMaterial.Bytes())
	mac := hmac.New(sha256.New, key[:])
	for _, part := range []string{attestation.Version, attestation.Nonce, attestation.Phase, attestation.CallIDHash, attestation.InputSHA256, "-", attestation.Model, attestation.Group, strconv.Itoa(attestation.ChannelID), attestation.RouteRevision, strconv.FormatInt(attestation.IssuedAt, 10), strconv.FormatInt(attestation.ExpiresAt, 10)} {
		require.NoError(t, binary.Write(mac, binary.BigEndian, uint32(len(part))))
		_, err := mac.Write([]byte(part))
		require.NoError(t, err)
	}
	assert.Equal(t, hex.EncodeToString(mac.Sum(nil)), attestation.Proof)
	var fields map[string]any
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &fields))
	assert.Len(t, fields, 13)
	for _, secret := range []string{"synthetic-access", "synthetic-id", "synthetic-refresh", "synthetic-account", "access_token", "refresh_token", "account_id"} {
		assert.NotContains(t, response.Body.String(), secret)
	}
	for _, change := range []map[string]any{{"nonce": strings.Repeat("d", 64)}, {"phase": "after"}, {"call_id_hash": strings.Repeat("d", 64)}, {"input_sha256": strings.Repeat("d", 64)}, {"schema_sha256": strings.Repeat("d", 64)}} {
		other := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, change))
		require.Equal(t, http.StatusOK, other.Code)
		var proof codexLocalAttestationResponse
		require.NoError(t, common.Unmarshal(other.Body.Bytes(), &proof))
		assert.NotEqual(t, attestation.Proof, proof.Proof, "proof must bind every invocation context")
		assert.Equal(t, attestation.RouteRevision, proof.RouteRevision)
	}
}

func TestCodexLocalAttestationRejectsDisabledMalformedAndNonSession(t *testing.T) {
	router, channel, token, identity := localAttestationFixture(t)
	body := localAttestationBody(t, nil)
	t.Setenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED", "false")
	assert.Equal(t, http.StatusNotFound, localAttestationRequest(router, channel.Id, "", body).Code)
	t.Setenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED", "true")
	for _, change := range []map[string]any{{"nonce": "short"}, {"nonce": strings.Repeat("A", 64)}, {"phase": "unknown"}, {"call_id_hash": 3}, {"input_sha256": ""}, {"schema_sha256": "bad"}, {"model": "other-model"}, {"group": "other-brand"}, {"prompt": "must-not-be-logged"}, {"model": strings.Repeat("x", 257)}} {
		response := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, change))
		assert.NotEqual(t, http.StatusOK, response.Code)
		assert.JSONEq(t, `{"error":"local_attestation_unavailable"}`, response.Body.String())
	}
	for _, malformed := range []string{`{`, body + `{}`, strings.Repeat(" ", 4097), strings.Replace(body, `,"schema_sha256":null`, "", 1)} {
		assert.Equal(t, http.StatusBadRequest, localAttestationRequest(router, channel.Id, token, malformed).Code)
	}
	patRaw := model.AccessTokenPrefix + strings.Repeat("p", 43)
	patToken := &model.UserAccessToken{Name: "synthetic-pat", TokenHash: model.AccessTokenFingerprint(patRaw), TokenHint: model.AccessTokenHint(patRaw)}
	require.NoError(t, patToken.SetScopes([]string{service.AccessTokenScopeOf(authz.ChannelSecretView)}))
	require.NoError(t, model.CreateUserAccessToken(identity.UserID, patToken, service.AccessTokenMaxPerUser))
	assert.Equal(t, http.StatusForbidden, localAttestationRequest(router, channel.Id, patRaw, body).Code)
	// An identity from a PAT, even if injected with a root role, cannot use this oracle.
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	c.Params = gin.Params{{Key: "id", Value: strconv.Itoa(channel.Id)}}
	c.Set("id", identity.UserID)
	c.Set("role", common.RoleRootUser)
	c.Set("session_id", model.AccessTokenSessionID(123))
	c.Set("auth_version", identity.UserAuthVersion)
	c.Set("session_version", int64(model.AccessTokenSessionVersion))
	CreateCodexLocalAttestation(c)
	assert.Equal(t, http.StatusForbidden, response.Code)
	_, err := model.RevokeUserSession(identity.UserID, identity.SessionID, "attestation-test")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, localAttestationRequest(router, channel.Id, token, body).Code)
}

func TestCodexLocalAttestationRejectsOrdinaryAndExpiredSessions(t *testing.T) {
	for _, condition := range []string{"ordinary-user", "expired-session"} {
		t.Run(condition, func(t *testing.T) {
			router, channel, token, identity := localAttestationFixture(t)
			if condition == "ordinary-user" {
				require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", identity.UserID).Update("role", common.RoleCommonUser).Error)
				require.NoError(t, model.PublishUserAuthCache(identity.UserID))
			} else {
				require.NoError(t, model.DB.Model(&model.UserSession{}).Where("sid = ?", identity.SessionID).Update("expires_at", time.Now().Unix()-1).Error)
			}
			response := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, nil))
			assert.GreaterOrEqual(t, response.Code, http.StatusUnauthorized)
			assert.NotContains(t, response.Body.String(), "proof")
		})
	}
}

func TestCodexLocalAttestationFreshRouteCredentialAndRevocation(t *testing.T) {
	router, channel, token, identity := localAttestationFixture(t)
	read := func() codexLocalAttestationResponse {
		response := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, nil))
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var result codexLocalAttestationResponse
		require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
		return result
	}
	before := read()
	key := strings.Replace(channel.Key, "synthetic-access", "rotated-access", 1)
	require.NoError(t, model.DB.Model(channel).Update("key", key).Error)
	rotated := read()
	assert.NotEqual(t, before.RouteRevision, rotated.RouteRevision)
	assert.NotEqual(t, before.Proof, rotated.Proof)
	// Operational counters and legacy polling metadata are not routing changes
	// for this strictly single-key path.
	require.NoError(t, model.DB.Model(channel).Updates(map[string]any{"response_time": 100, "used_quota": 10, "channel_info": model.ChannelInfo{MultiKeyPollingIndex: 4}}).Error)
	assert.Equal(t, rotated.RouteRevision, read().RouteRevision)
	priority := int64(2)
	require.NoError(t, model.DB.Model(channel).Update("priority", priority).Error)
	assert.NotEqual(t, rotated.RouteRevision, read().RouteRevision)
	for _, update := range []map[string]any{{"status": 2}, {"type": 1}, {"channel_info": model.ChannelInfo{IsMultiKey: true}}, {"key": `{"access_token":"missing-other-material"}`}, {"key": strings.Replace(key, `"account_id":`, `"type":"unrelated","account_id":`, 1)}} {
		require.NoError(t, model.DB.Model(channel).Updates(update).Error)
		assert.Equal(t, http.StatusConflict, localAttestationRequest(router, channel.Id, token, localAttestationBody(t, nil)).Code)
		require.NoError(t, model.DB.Model(channel).Updates(map[string]any{"status": common.ChannelStatusEnabled, "type": constant.ChannelTypeCodex, "channel_info": model.ChannelInfo{}, "key": key}).Error)
	}
	// Revoke during the fresh channel read, not just before the HTTP request.
	callback := "test:attestation-revoke-during-read"
	require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "channels" {
			_, err := model.RevokeUserSession(identity.UserID, identity.SessionID, "during-attestation")
			require.NoError(t, err)
		}
	}))
	t.Cleanup(func() { model.DB.Callback().Query().Remove(callback) })
	response := localAttestationRequest(router, channel.Id, token, localAttestationBody(t, nil))
	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.NotContains(t, response.Body.String(), "proof")
}
