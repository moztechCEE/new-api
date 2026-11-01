package controller

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

const localOwnerSourceViewVersion = "new-api.owner-local-source-view.v1"

// This is a bounded interval view, not an atomic database snapshot or a
// nonce-bound attestation. The independent per-invocation before/after Codex
// credential proof remains necessary. No routing data or credentials are
// returned: the keyed revision only detects changes within this owner session.
type localOwnerSourceViewResponse struct {
	Version         string                    `json:"version"`
	Self            localOwnerSourceViewUser  `json:"self"`
	Sessions        []localOwnerSourceSession `json:"sessions"`
	RoutingRevision string                    `json:"routingRevision"`
	ChannelCount    int                       `json:"channelCount"`
	TokenCount      int                       `json:"tokenCount"`
}

type localOwnerSourceViewUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     int    `json:"role"`
	Status   int    `json:"status"`
}

type localOwnerSourceSession struct {
	SID       string `json:"sid"`
	Current   bool   `json:"current"`
	ExpiresAt int64  `json:"expires_at"`
}

// These fields are exactly the existing local routing projection, not the
// entire model DTO. In particular channel.key and token.key are neither read
// from the database nor included in the revision. Opaque values stay opaque.
type localOwnerRoutingChannel struct {
	ID                int               `json:"id"`
	Type              int               `json:"type"`
	Status            int               `json:"status"`
	Name              string            `json:"name"`
	Group             string            `json:"group"`
	Models            string            `json:"models"`
	BaseURL           *string           `json:"base_url"`
	TestModel         *string           `json:"test_model"`
	Priority          *int64            `json:"priority"`
	Weight            *uint             `json:"weight"`
	AutoBan           *int              `json:"auto_ban"`
	Setting           *string           `json:"setting"`
	Settings          string            `json:"settings"`
	ModelMapping      *string           `json:"model_mapping"`
	StatusCodeMapping *string           `json:"status_code_mapping"`
	ParamOverride     *string           `json:"param_override"`
	HeaderOverride    *string           `json:"header_override"`
	ChannelInfo       model.ChannelInfo `json:"channel_info"`
}

type localOwnerRoutingToken struct {
	ID                  int    `json:"id"`
	Status              int    `json:"status"`
	Name                string `json:"name"`
	Group               string `json:"group"`
	ExpiredTime         int64  `json:"expired_time"`
	UnlimitedQuota      bool   `json:"unlimited_quota"`
	ModelLimitsEnabled  bool   `json:"model_limits_enabled"`
	ModelLimits         string `json:"model_limits"`
	CrossGroupRetry     bool   `json:"cross_group_retry"`
	AllowUserQuotaQuery bool   `json:"allow_user_quota_query"`
}

// CreateLocalOwnerSourceView uses the normal dashboard identity, capability,
// current-user/session and safe option semantics without HTTP handler recursion.
// The dedicated local gate is repeated here so a direct handler call cannot
// bypass it. Every request performs new reads; there is no cross-phase cache.
func CreateLocalOwnerSourceView(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !localOwnerSourceViewPeerAllowed(c.Request.RemoteAddr) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if c.Request.Method != http.MethodGet || c.Request.URL.RawQuery != "" || c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0 ||
		c.Request.Body != nil && c.Request.Body != http.NoBody {
		localOwnerSourceViewError(c, http.StatusBadRequest)
		return
	}
	identity, ok := middleware.GetSessionAuthIdentity(c)
	_, pat := model.ParseAccessTokenSessionID(identity.SessionID)
	role := c.GetInt("role")
	if !ok || pat || c.GetBool("use_access_token") || role < common.RoleRootUser ||
		!authz.Can(identity.UserID, role, authz.ChannelRead) || !authz.Can(identity.UserID, role, authz.ChannelSecretView) {
		localOwnerSourceViewError(c, http.StatusForbidden)
		return
	}
	if err := service.ValidateStepUpIdentity(identity); err != nil {
		localOwnerSourceViewError(c, http.StatusForbidden)
		return
	}
	view, err := localOwnerSourceView(c.Request.Context(), identity, role)
	if err != nil {
		localOwnerSourceViewError(c, http.StatusConflict)
		return
	}
	if err := service.ValidateStepUpIdentity(identity); err != nil {
		localOwnerSourceViewError(c, http.StatusForbidden)
		return
	}
	currentSession, err := localOwnerCurrentSession(c.Request.Context(), identity)
	if err != nil {
		localOwnerSourceViewError(c, http.StatusForbidden)
		return
	}
	// Re-read the normal safe user row as well: a role/status change during the
	// interval must not rely only on the role captured by the first middleware.
	currentUser, err := localOwnerSourceUser(c.Request.Context(), identity.UserID)
	if err != nil || currentUser.Role != role || currentUser.Status != common.UserStatusEnabled || currentUser.AuthVersion != identity.UserAuthVersion ||
		!authz.Can(identity.UserID, currentUser.Role, authz.ChannelRead) || !authz.Can(identity.UserID, currentUser.Role, authz.ChannelSecretView) || c.Request.Context().Err() != nil {
		localOwnerSourceViewError(c, http.StatusForbidden)
		return
	}
	view.Sessions = []localOwnerSourceSession{currentSession}
	common.ApiSuccess(c, view)
}

// Read only the live owner-session binding, never its refresh hash. Normal
// authentication remains required, but a warmed positive session cache is not
// evidence that a revocation/version change did not occur during this interval.
func localOwnerCurrentSession(ctx context.Context, identity service.AuthIdentity) (localOwnerSourceSession, error) {
	var session struct {
		SID             string `gorm:"column:sid"`
		UserID          int
		Version         int64
		UserAuthVersion int64
		Status          string
		RevokedAt       int64
		ExpiresAt       int64
	}
	err := model.DB.WithContext(ctx).Model(&model.UserSession{}).Select([]string{
		"sid", "user_id", "version", "user_auth_version", "status", "revoked_at", "expires_at",
	}).Where("sid = ? AND user_id = ?", identity.SessionID, identity.UserID).Take(&session).Error
	if err != nil || session.UserID != identity.UserID || session.SID != identity.SessionID ||
		session.Version != identity.SessionVersion || session.UserAuthVersion != identity.UserAuthVersion ||
		session.Status != model.UserSessionStatusActive || session.RevokedAt != 0 || session.ExpiresAt <= time.Now().Unix() {
		return localOwnerSourceSession{}, errors.New("local owner source view unavailable")
	}
	return localOwnerSourceSession{SID: session.SID, Current: true, ExpiresAt: session.ExpiresAt}, nil
}

func localOwnerSourceUser(ctx context.Context, userID int) (*model.User, error) {
	var user model.User
	err := model.DB.WithContext(ctx).Model(&model.User{}).Select([]string{
		"id", "username", "role", "status", "setting", "auth_version",
	}).Where("id = ?", userID).Take(&user).Error
	return &user, err
}

func localOwnerSourceView(ctx context.Context, identity service.AuthIdentity, role int) (*localOwnerSourceViewResponse, error) {
	const rowLimit = 100
	held := errors.New("local owner source view unavailable")
	user, err := localOwnerSourceUser(ctx, identity.UserID)
	if err != nil || user.Id != identity.UserID || user.Role != role || user.Status != common.UserStatusEnabled || user.AuthVersion != identity.UserAuthVersion {
		return nil, held
	}
	current, err := localOwnerCurrentSession(ctx, identity)
	if err != nil {
		return nil, held
	}
	var channelCount, tokenCount int64
	if err := buildChannelListQuery("", -1, -1).WithContext(ctx).Count(&channelCount).Error; err != nil || channelCount > rowLimit {
		return nil, held
	}
	// Select the same projection as the existing normal list, but never select
	// either credential column. No request parameter can alter IDs, SQL or scope.
	var channelRows []model.Channel
	if err := buildChannelListQuery("", -1, -1).WithContext(ctx).Select([]string{
		"id", "type", "status", "name", "group", "models", "base_url", "test_model", "priority", "weight", "auto_ban",
		"setting", "settings", "model_mapping", "status_code_mapping", "param_override", "header_override", "channel_info",
	}).Order("id ASC").Limit(rowLimit + 1).Find(&channelRows).Error; err != nil || int64(len(channelRows)) != channelCount {
		return nil, held
	}
	if err := model.DB.WithContext(ctx).Model(&model.Token{}).Where("user_id = ?", identity.UserID).Count(&tokenCount).Error; err != nil || tokenCount > rowLimit {
		return nil, held
	}
	var tokenRows []localOwnerRoutingToken
	if err := model.DB.WithContext(ctx).Model(&model.Token{}).Where("user_id = ?", identity.UserID).Select([]string{
		"id", "status", "name", "group", "expired_time", "unlimited_quota", "model_limits_enabled", "model_limits", "cross_group_retry", "allow_user_quota_query",
	}).Order("id ASC").Limit(rowLimit + 1).Find(&tokenRows).Error; err != nil || int64(len(tokenRows)) != tokenCount {
		return nil, held
	}
	channels := make([]localOwnerRoutingChannel, 0, len(channelRows))
	for i := range channelRows {
		row := &channelRows[i]
		clearChannelInfo(row)
		channels = append(channels, localOwnerRoutingChannel{row.Id, row.Type, row.Status, row.Name, row.Group, row.Models,
			row.BaseURL, row.TestModel, row.Priority, row.Weight, row.AutoBan, row.Setting, row.OtherSettings,
			row.ModelMapping, row.StatusCodeMapping, row.ParamOverride, row.HeaderOverride, row.ChannelInfo})
	}
	options, err := dashboardOptionSnapshot()
	if err != nil {
		return nil, held
	}
	revision, err := localOwnerRoutingRevision(identity, user, channels, tokenRows, options)
	if err != nil {
		return nil, held
	}
	// Refuse count/truncation races, rather than returning a partial inventory.
	var channelCountAfter int64
	var tokenCountAfter int64
	if err := model.DB.WithContext(ctx).Model(&model.Token{}).Where("user_id = ?", identity.UserID).Count(&tokenCountAfter).Error; err != nil || tokenCountAfter != tokenCount ||
		buildChannelListQuery("", -1, -1).WithContext(ctx).Count(&channelCountAfter).Error != nil || channelCountAfter != channelCount {
		return nil, held
	}
	return &localOwnerSourceViewResponse{Version: localOwnerSourceViewVersion,
		Self: localOwnerSourceViewUser{user.Id, user.Username, user.Role, user.Status}, Sessions: []localOwnerSourceSession{current},
		RoutingRevision: revision, ChannelCount: len(channels), TokenCount: len(tokenRows)}, nil
}

func localOwnerRoutingRevision(identity service.AuthIdentity, user *model.User, channels []localOwnerRoutingChannel, tokens []localOwnerRoutingToken, options []*model.Option) (string, error) {
	if strings.TrimSpace(common.SessionSecret) == "" {
		return "", errors.New("local owner source view unavailable")
	}
	// Preserve all opaque values exactly. Only unordered option keys and row IDs
	// are normalized, as in the prior local projection; duplicate keys fail closed.
	normalOptions := slices.Clone(options)
	for _, option := range normalOptions {
		if option == nil {
			return "", errors.New("local owner source view unavailable")
		}
	}
	slices.SortFunc(normalOptions, func(a, b *model.Option) int { return strings.Compare(a.Key, b.Key) })
	for i, option := range normalOptions {
		if option == nil || option.Key == "" || i > 0 && option.Key == normalOptions[i-1].Key {
			return "", errors.New("local owner source view unavailable")
		}
	}
	channels = slices.Clone(channels)
	tokens = slices.Clone(tokens)
	slices.SortFunc(channels, func(a, b localOwnerRoutingChannel) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(tokens, func(a, b localOwnerRoutingToken) int { return cmp.Compare(a.ID, b.ID) })
	preimage := struct {
		Version  string
		Actor    service.AuthIdentity
		Channels []localOwnerRoutingChannel
		Tokens   []localOwnerRoutingToken
		Options  []*model.Option
		Self     struct {
			ID, Role, Status int
			Setting          string
		}
	}{Version: localOwnerSourceViewVersion, Actor: identity, Channels: channels, Tokens: tokens, Options: normalOptions}
	preimage.Self.ID, preimage.Self.Role, preimage.Self.Status, preimage.Self.Setting = user.Id, user.Role, user.Status, user.Setting
	encoded, err := common.Marshal(preimage)
	if err != nil {
		return "", err
	}
	key := hmac.New(sha256.New, []byte(common.SessionSecret))
	_, _ = key.Write([]byte("new-api/owner-local/source-view/key/v1"))
	mac := hmac.New(sha256.New, key.Sum(nil))
	_, _ = mac.Write([]byte("new-api.owner-local-source-view.revision.v1\x00"))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// LocalOwnerSourceViewGate is an additional transport boundary, never an
// authentication substitute. Docker loopback publishing can present a bridge
// peer to Go, so only one explicitly configured exact private peer is accepted
// in addition to real socket loopback. Forwarding headers are not consulted.
func LocalOwnerSourceViewGate(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !localOwnerSourceViewPeerAllowed(c.Request.RemoteAddr) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Next()
}

func localOwnerSourceViewPeerAllowed(remoteAddr string) bool {
	if os.Getenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED") != "true" {
		return false
	}
	var trusted netip.Addr
	if raw := os.Getenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER"); raw != "" {
		var err error
		trusted, err = netip.ParseAddr(raw)
		if err != nil || trusted.Zone() != "" {
			return false
		}
		trusted = trusted.Unmap()
		if !trusted.IsPrivate() || trusted.IsUnspecified() || trusted.IsMulticast() {
			return false
		}
	}
	address, err := netip.ParseAddrPort(remoteAddr)
	if err != nil || address.Addr().Zone() != "" {
		return false
	}
	peer := address.Addr().Unmap()
	return peer.IsLoopback() || trusted.IsValid() && peer == trusted
}

func localOwnerSourceViewError(c *gin.Context, status int) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": "local_owner_source_view_unavailable"})
}
