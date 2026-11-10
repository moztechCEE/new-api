package router

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaydto "github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// Real dashboard PAT and relay TokenAuth over disposable SQLite. The installer
// never calls inference: this fixture reaches only /api/token and /v1/models.
func TestCorelySIWCOrdinaryOwnerGatewayTokenInstallerWire(t *testing.T) {
	oldDB, oldLogDB := model.DB, model.LOG_DB
	t.Cleanup(func() { model.DB, model.LOG_DB = oldDB, oldLogDB })
	setupRelayRouterTestDB(t)
	require.NoError(t, i18n.Init())
	require.NoError(t, model.DB.AutoMigrate(&model.UserAccessToken{}, &model.AuditLog{}, &model.Channel{}))

	const group, sol, ip = "corely-siwc-wire-fixture", "gpt-6.1-sol", "127.0.0.1"
	oldRatios := ratio_setting.GroupRatio2JSONString()
	t.Cleanup(func() { require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(oldRatios)) })
	ratio_setting.GetGroupRatioSetting().GroupRatio.Set(group, 0)
	makeOwner := func(name string) model.User {
		user := model.User{Username: name, Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: group, Quota: 100, AffCode: name}
		user.SetSetting(relaydto.UserSetting{AcceptUnsetRatioModel: true})
		require.NoError(t, model.DB.Create(&user).Error)
		return user
	}
	owner, other := makeOwner("corely-fixture-owner"), makeOwner("corely-other-owner")
	const rawPAT = "nap_0123456789abcdefghijklmnopqrstuvwxyz012345z"
	makePAT := func(user model.User, raw string, scopes ...string) {
		pat := model.UserAccessToken{UserId: user.Id, Name: "fixture-ordinary-PAT", TokenHash: model.AccessTokenFingerprint(raw),
			TokenHint: model.AccessTokenHint(raw), ExpiresAt: time.Now().Add(2 * time.Hour).Unix(), CreatedAt: time.Now().Unix()}
		require.NoError(t, pat.SetScopes(scopes))
		require.NoError(t, model.DB.Create(&pat).Error)
	}
	// The actual PAT generator uses 43 alphanumerics, not canonical base64url.
	require.Len(t, rawPAT, len("nap_")+43)
	makePAT(owner, rawPAT, "profile:read", "api_key:read", "api_key:reveal", "api_key:write")
	otherPAT := strings.Replace(rawPAT, "nap_0", "nap_1", 1)
	makePAT(other, otherPAT, "api_key:write")
	base := "http://127.0.0.1:1"
	channel := model.Channel{Type: constant.ChannelTypeOpenAI, Status: common.ChannelStatusEnabled,
		Name: "corely-fixture-never-dial", Group: group, Models: sol, BaseURL: &base, Key: "fixture-never-used"}
	require.NoError(t, model.DB.Create(&channel).Error)
	require.NoError(t, model.DB.Create(&model.Ability{Group: group, Model: sol, ChannelId: channel.Id, Enabled: true}).Error)

	engine := gin.New()
	require.NoError(t, engine.SetTrustedProxies(nil))
	engine.Use(middleware.RequestId(), middleware.I18n())
	SetApiRouter(engine)
	SetRelayRouter(engine)
	call := func(method, path, bearer string, uid int, body any) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		var input io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			require.NoError(t, err)
			input = strings.NewReader(string(encoded))
		}
		req := httptest.NewRequest(method, path, input)
		req.RemoteAddr = ip + ":43210"
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Language", "en")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Cache-Control", "no-cache, no-store")
		req.Header.Set("Pragma", "no-cache")
		if uid != 0 {
			req.Header.Set("New-Api-User", strconv.Itoa(uid))
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, req)
		require.Regexp(t, `(?i)^application/json(;\s*charset=utf-8)?$`, recorder.Header().Get("Content-Type"), recorder.Body.String())
		require.Empty(t, recorder.Header().Get("Content-Encoding"))
		var response map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		return recorder, response
	}
	dashboard := func(method, path string, body any) map[string]any {
		t.Helper()
		res, value := call(method, path, rawPAT, owner.Id, body)
		require.Equal(t, http.StatusOK, res.Code, "%s %s: %s", method, path, res.Body.String())
		require.Equal(t, true, value["success"], "%s %s: %s", method, path, res.Body.String())
		require.Equal(t, "", value["message"], "%s %s", method, path)
		return value
	}
	self := dashboard(http.MethodGet, "/api/user/self", nil)["data"].(map[string]any)
	require.Equal(t, float64(owner.Id), self["id"])
	require.Equal(t, float64(common.RoleCommonUser), self["role"])
	require.Equal(t, float64(common.UserStatusEnabled), self["status"])
	require.Equal(t, group, self["group"])

	search := func(name string) []any {
		t.Helper()
		data := dashboard(http.MethodGet, "/api/token/search?keyword="+url.QueryEscape(name)+"&p=1&page_size=10", nil)["data"].(map[string]any)
		rows, ok := data["items"].([]any)
		require.True(t, ok, "installer expects an items array even on an empty search")
		require.Equal(t, float64(len(rows)), data["total"])
		return rows
	}
	create := func(generation int, expiresAt int64) (int, string) {
		t.Helper()
		name := fmt.Sprintf("corely-siwc-0123456789abcdef01-%d", generation)
		require.Empty(t, search(name))
		dashboard(http.MethodPost, "/api/token/", map[string]any{
			"name": name, "expired_time": expiresAt, "group": group, "allow_ips": ip,
			"model_limits_enabled": true, "model_limits": sol, "cross_group_retry": false,
			"allow_user_quota_query": false, "auto_groups": nil, "unlimited_quota": false, "remain_quota": 1,
		})
		rows := search(name)
		require.Len(t, rows, 1)
		scoped := rows[0].(map[string]any)
		id := int(scoped["id"].(float64))
		require.Positive(t, id)
		for field, value := range map[string]any{"user_id": float64(owner.Id), "name": name, "status": float64(1),
			"expired_time": float64(expiresAt), "model_limits_enabled": true, "model_limits": sol, "group": group, "allow_ips": ip,
			"cross_group_retry": false, "auto_groups": nil, "unlimited_quota": false, "remain_quota": float64(1), "allow_user_quota_query": false} {
			require.Contains(t, scoped, field)
			require.Equal(t, value, scoped[field], field)
		}
		path := "/api/token/" + strconv.Itoa(id)
		require.Equal(t, scoped, dashboard(http.MethodGet, path, nil)["data"])
		key := dashboard(http.MethodPost, path+"/key", nil)["data"].(map[string]any)
		require.Len(t, key, 1)
		raw := key["key"].(string)
		require.Regexp(t, `^[A-Za-z0-9]{48}$`, raw)
		require.Equal(t, model.MaskTokenKey(raw), scoped["key"])
		return id, raw
	}
	probeIDs := map[string]bool{}
	probe := func(raw string, retired bool) {
		t.Helper()
		res, value := call(http.MethodGet, "/v1/models", "sk-"+raw, 0, nil)
		requestID := res.Header().Get("X-Oneapi-Request-Id")
		require.Regexp(t, `^[a-zA-Z0-9._-]{1,128}$`, requestID)
		require.False(t, probeIDs[requestID])
		probeIDs[requestID] = true
		require.Contains(t, []string{"", "0"}, res.Header().Get("Age"))
		if retired {
			require.Equal(t, http.StatusUnauthorized, res.Code)
			require.Equal(t, map[string]any{"error": map[string]any{"type": "new_api_error", "code": "",
				"message": "Invalid token (request id: " + requestID + ")"}}, value)
			return
		}
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		require.Len(t, value, 3)
		require.Equal(t, true, value["success"])
		require.Equal(t, "list", value["object"])
		models := value["data"].([]any)
		require.Len(t, models, 1)
		require.Equal(t, sol, models[0].(map[string]any)["id"])
	}

	originalExpiry := time.Now().Add(90 * time.Minute).Unix()
	oldID, original := create(1, originalExpiry)
	probe(original, false)
	nextID, successor := create(2, time.Now().Add(100*time.Minute).Unix())
	require.NotEqual(t, oldID, nextID)
	require.NotEqual(t, original, successor)
	probe(successor, false)
	_, forbidden := call(http.MethodDelete, "/api/token/"+strconv.Itoa(oldID), otherPAT, other.Id, nil)
	require.Equal(t, false, forbidden["success"])
	probe(original, false)
	dashboard(http.MethodDelete, "/api/token/"+strconv.Itoa(oldID), nil)
	var deleted model.Token
	require.NoError(t, model.DB.Unscoped().First(&deleted, oldID).Error)
	require.True(t, deleted.DeletedAt.Valid)
	require.Equal(t, originalExpiry, deleted.ExpiredTime)
	require.Greater(t, originalExpiry, time.Now().Unix(), "old credential is revoked, not naturally expired")
	probe(original, true)
	probe(successor, false)
}
