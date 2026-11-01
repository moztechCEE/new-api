package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	sqlmysql "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func localOwnerSourceMatrixConfig(dialect, dsn string) error {
	held := errors.New("source-view matrix requires an explicit dedicated test database")
	if dialect == "" && dsn == "" {
		return nil
	}
	if dialect == "" || dsn == "" {
		return held
	}
	switch dialect {
	case "postgres":
		parsed, err := url.Parse(dsn)
		if err != nil || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" || parsed.Port() != "55526" ||
			!net.ParseIP(parsed.Hostname()).IsLoopback() || parsed.Fragment != "" {
			return held
		}
	case "mysql":
		parsed, err := sqlmysql.ParseDSN(dsn)
		if err != nil || parsed.Net != "tcp" || parsed.MultiStatements {
			return held
		}
		host, port, err := net.SplitHostPort(parsed.Addr)
		if err != nil || port != "33326" || !net.ParseIP(host).IsLoopback() {
			return held
		}
	default:
		return held
	}
	return nil
}

// Optional matrix fixtures connect only to root-created disposable servers.
// Every DB-needing fixture creates a fresh database; names cannot be supplied
// by the caller, collisions fail, and neither an old DB nor a table is dropped.
func localOwnerSourceEnrollmentFixture(t *testing.T) *model.User {
	t.Helper()
	dialect, baseDSN := os.Getenv("NEW_API_SOURCE_VIEW_TEST_DIALECT"), os.Getenv("NEW_API_SOURCE_VIEW_TEST_BASE_DSN")
	require.NoError(t, localOwnerSourceMatrixConfig(dialect, baseDSN))
	if dialect == "" {
		user, _ := setupSecurityEnrollmentTest(t)
		return user
	}
	var random [12]byte
	_, err := rand.Read(random[:])
	require.NoError(t, err)
	name := "source_view_v56_" + hex.EncodeToString(random[:])
	var adminDriver, isolatedDriver gorm.Dialector
	if dialect == "postgres" {
		parsed, err := url.Parse(baseDSN)
		require.NoError(t, err)
		adminDriver = postgres.Open(baseDSN)
		parsed.Path, parsed.RawPath = "/"+name, ""
		isolatedDriver = postgres.Open(parsed.String())
	} else {
		parsed, err := sqlmysql.ParseDSN(baseDSN)
		require.NoError(t, err)
		adminDriver = mysql.Open(baseDSN)
		parsed.DBName = name
		isolatedDriver = mysql.Open(parsed.FormatDSN())
	}
	admin, err := gorm.Open(adminDriver, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	create := "CREATE DATABASE " + name
	if dialect == "mysql" {
		create += " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
	}
	createErr := admin.Exec(create).Error
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	require.NoError(t, adminSQL.Close())
	require.NoError(t, createErr)
	db, err := gorm.Open(isolatedDriver, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	previousRedis, previousSecret := common.RedisEnabled, common.SessionSecret
	model.DB, model.LOG_DB = db, db
	dbType := common.DatabaseTypePostgreSQL
	if dialect == "mysql" {
		dbType = common.DatabaseTypeMySQL
	}
	common.SetDatabaseTypes(dbType, dbType)
	common.RedisEnabled, common.SessionSecret = false, "source-view-matrix-synthetic-session-secret"
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.SetDatabaseTypes(previousMain, previousLog)
		common.RedisEnabled, common.SessionSecret = previousRedis, previousSecret
		connection, err := db.DB()
		if err == nil {
			_ = connection.Close()
		}
	})
	require.NoError(t, i18n.Init())
	gin.SetMode(gin.TestMode)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{},
		&model.AuthFlow{}, &model.UserOAuthBinding{}, &model.Option{}, &model.UserAccessToken{}, &model.AuditLog{}))
	require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))
	var version string
	require.NoError(t, db.Raw("SELECT VERSION()").Scan(&version).Error)
	t.Logf("database: %s %s", dialect, version)
	user := &model.User{Username: "source-view-owner", AffCode: "source-view-owner", Password: "synthetic-unused-password", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1}
	require.NoError(t, db.Create(user).Error)
	require.NoError(t, model.PublishUserAuthCache(user.Id))
	return user
}

func localOwnerSourceFixture(t *testing.T) (*gin.Engine, *model.User, *service.AuthBundle, *model.Channel, *model.Token) {
	t.Helper()
	user := localOwnerSourceEnrollmentFixture(t)
	require.NoError(t, model.DB.AutoMigrate(&model.Channel{}, &model.Token{}))
	require.NoError(t, model.DB.Model(user).Updates(map[string]any{"role": common.RoleRootUser, "setting": `{"private_note":"synthetic-user-setting"}`}).Error)
	user.Role = common.RoleRootUser
	require.NoError(t, model.PublishUserAuthCache(user.Id))
	bundle, err := service.CreateLoginSession(user.Id, "password", "127.0.0.1", "synthetic-source-view")
	require.NoError(t, err)
	baseURL, opaque := "https://synthetic.invalid", `{"Authorization":"synthetic-opaque-credential"}`
	channel := &model.Channel{Type: constant.ChannelTypeCodex, Status: 1, Name: "synthetic-source-channel", Group: "synthetic-group", Models: "synthetic-model",
		Key: "synthetic-channel-key-never-read", BaseURL: &baseURL, HeaderOverride: &opaque}
	require.NoError(t, model.DB.Create(channel).Error)
	token := &model.Token{UserId: user.Id, Status: 1, Name: "synthetic-source-token", Key: "synthetic-relay-key-never-read", Group: "synthetic-group", ModelLimits: "synthetic-model"}
	require.NoError(t, model.DB.Create(token).Error)
	oldOptions := common.OptionMap
	common.OptionMap = map[string]string{"RetryTimes": "0", "OpaqueAllowedOption": "synthetic-opaque-option", "SecretToken": "synthetic-filtered-secret"}
	t.Cleanup(func() { common.OptionMap = oldOptions })
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED", "true")
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER", "")
	router := gin.New()
	middleware.DeclareAccessTokenPermissionRoute(http.MethodGet, "/api/local-owner/source-view", authz.ChannelRead)
	router.GET("/api/local-owner/source-view", LocalOwnerSourceViewGate, middleware.RootAuth(),
		middleware.RequirePermission(authz.ChannelRead), middleware.RequirePermission(authz.ChannelSecretView), CreateLocalOwnerSourceView)
	return router, user, bundle, channel, token
}

func TestLocalOwnerSourceViewMatrixRejectsUnknownOrExistingDatabaseTargets(t *testing.T) {
	assert.NoError(t, localOwnerSourceMatrixConfig("", ""))
	assert.NoError(t, localOwnerSourceMatrixConfig("postgres", "postgres://synthetic@127.0.0.1:55526/postgres?sslmode=disable"))
	assert.NoError(t, localOwnerSourceMatrixConfig("mysql", "synthetic@tcp(127.0.0.1:33326)/mysql"))
	for _, input := range [][2]string{
		{"", "postgres://synthetic@127.0.0.1:55526/postgres"}, {"postgres", ""}, {"sqlite", "sqlite.db"}, {"unknown", "unknown"},
		{"postgres", "postgres://synthetic@127.0.0.1:55492/postgres"}, {"postgres", "postgres://synthetic@192.0.2.1:55526/postgres"},
		{"postgres", "https://127.0.0.1:55526/postgres"}, {"postgres", "postgres://synthetic@localhost:55526/postgres"},
		{"mysql", "synthetic@tcp(127.0.0.1:3306)/mysql"}, {"mysql", "synthetic@tcp(192.0.2.1:33326)/mysql"},
		{"mysql", "synthetic@unix(/tmp/source-view.sock)/mysql"}, {"mysql", "synthetic@tcp(127.0.0.1:33326)/mysql?multiStatements=true"},
	} {
		assert.Error(t, localOwnerSourceMatrixConfig(input[0], input[1]), "invalid matrix configuration must fail, never skip")
	}
}

func localOwnerSourceRequest(router http.Handler, bearer, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Authorization", "Bearer "+bearer)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func decodeLocalOwnerSourceView(t *testing.T, response *httptest.ResponseRecorder) localOwnerSourceViewResponse {
	t.Helper()
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var envelope struct {
		Success bool              `json:"success"`
		Message string            `json:"message"`
		Data    common.RawMessage `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	require.True(t, envelope.Success)
	assert.Empty(t, envelope.Message)
	var outer, data map[string]any
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &outer))
	require.NoError(t, common.Unmarshal(envelope.Data, &data))
	assert.Len(t, outer, 3)
	assert.Len(t, data, 6)
	var view localOwnerSourceViewResponse
	require.NoError(t, common.Unmarshal(envelope.Data, &view))
	return view
}

func TestLocalOwnerSourceViewExactSocketPeerAndDefaultOff(t *testing.T) {
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER", "")
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED", "")
	assert.False(t, localOwnerSourceViewPeerAllowed("127.0.0.1:1234"))
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED", "true")
	for _, peer := range []string{"127.0.0.1:1234", "[::1]:1234", "[::ffff:127.0.0.1]:1234"} {
		assert.True(t, localOwnerSourceViewPeerAllowed(peer), peer)
	}
	for _, peer := range []string{"192.168.65.1:1234", "192.0.2.1:1234", "127.0.0.1", "127.0.0.1:bad", "127.0.0.1:65536", "localhost:1234", "[::1%eth0]:1234"} {
		assert.False(t, localOwnerSourceViewPeerAllowed(peer), peer)
	}
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER", "192.168.65.1")
	assert.True(t, localOwnerSourceViewPeerAllowed("192.168.65.1:1234"))
	assert.False(t, localOwnerSourceViewPeerAllowed("192.168.65.2:1234"))
	for _, configured := range []string{"192.168.65.0/24", "192.168.65.1,192.168.65.2", "0.0.0.0", "192.0.2.1", "localhost", "::1%eth0"} {
		t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER", configured)
		assert.False(t, localOwnerSourceViewPeerAllowed("127.0.0.1:1234"), configured)
	}
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_TRUSTED_PEER", "")
	router := gin.New()
	router.GET("/", LocalOwnerSourceViewGate, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("Forwarded", "for=127.0.0.1")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assert.Equal(t, http.StatusNotFound, response.Code)
}

func TestLocalOwnerSourceViewNormalSessionMinimalResponseAndRefresh(t *testing.T) {
	router, user, bundle, _, _ := localOwnerSourceFixture(t)
	read := func(bearer string) localOwnerSourceViewResponse {
		response := localOwnerSourceRequest(router, bearer, "/api/local-owner/source-view")
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		for _, secret := range []string{"synthetic-channel-key", "synthetic-relay-key", "synthetic-opaque-credential", "synthetic-user-setting", "synthetic-opaque-option", "synthetic-filtered-secret", bundle.RefreshToken, bundle.AccessToken, "header_override", "refresh_token", "channel_info", "email", "user_agent"} {
			assert.NotContains(t, response.Body.String(), secret)
		}
		result := decodeLocalOwnerSourceView(t, response)
		assert.Equal(t, "new-api.owner-local-source-view.v1", result.Version)
		assert.Equal(t, localOwnerSourceViewUser{user.Id, user.Username, common.RoleRootUser, 1}, result.Self)
		require.Len(t, result.Sessions, 1)
		assert.Equal(t, localOwnerSourceSession{bundle.Session.SID, true, bundle.Session.ExpiresAt}, result.Sessions[0])
		assert.Equal(t, 1, result.ChannelCount)
		assert.Equal(t, 1, result.TokenCount)
		assert.Regexp(t, `^[0-9a-f]{64}$`, result.RoutingRevision)
		return result
	}
	first := read(bundle.AccessToken)
	assert.Equal(t, first.RoutingRevision, read(bundle.AccessToken).RoutingRevision)
	refreshed, _, err := service.RefreshLoginSession(bundle.RefreshToken, bundle.Session.SID, "127.0.0.1", "synthetic-source-view")
	require.NoError(t, err)
	assert.Equal(t, first.RoutingRevision, read(refreshed.AccessToken).RoutingRevision)

	// Another user's token must neither change this owner's view nor be read.
	foreign := &model.User{Username: "foreign-source-user", AffCode: "synthetic-foreign-aff", Role: common.RoleCommonUser, Status: 1, AuthVersion: 1}
	require.NoError(t, model.DB.Create(foreign).Error)
	require.NoError(t, model.DB.Create(&model.Token{UserId: foreign.Id, Name: "foreign-source-token", Key: "foreign-secret-never-read"}).Error)
	assert.Equal(t, first.RoutingRevision, read(refreshed.AccessToken).RoutingRevision)
	queries := make([]string, 0)
	callback := "test:local-source-no-credential-select"
	require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "channels" || tx.Statement.Table == "tokens" {
			queries = append(queries, tx.Statement.SQL.String())
		}
	}))
	t.Cleanup(func() { model.DB.Callback().Query().Remove(callback) })
	read(refreshed.AccessToken)
	require.NotEmpty(t, queries)
	for _, query := range queries {
		assert.NotContains(t, strings.ToLower(query), "select *")
		assert.NotContains(t, query, "`key`")
		assert.NotContains(t, query, `"key"`)
	}
}

func TestLocalOwnerSourceViewEveryRoutingFieldChangesRevision(t *testing.T) {
	router, _, bundle, channel, token := localOwnerSourceFixture(t)
	require.NoError(t, model.DB.Omit("key").First(channel, channel.Id).Error)
	read := func() string {
		response := localOwnerSourceRequest(router, bundle.AccessToken, "/api/local-owner/source-view")
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		return decodeLocalOwnerSourceView(t, response).RoutingRevision
	}
	baseline := read()
	channelFields := []struct {
		column            string
		changed, original any
	}{
		{"id", channel.Id + 100, channel.Id}, {"type", 58, channel.Type}, {"status", 2, channel.Status}, {"name", "changed-channel", channel.Name},
		{"group", "changed-group", channel.Group}, {"models", "changed-model", channel.Models}, {"base_url", "https://other.invalid", *channel.BaseURL},
		{"test_model", "other-model", channel.TestModel}, {"priority", 2, channel.Priority}, {"weight", 2, channel.Weight}, {"auto_ban", 0, channel.AutoBan},
		{"setting", "opaque-setting", channel.Setting}, {"settings", "opaque-settings", channel.OtherSettings}, {"model_mapping", `{"a":"b"}`, channel.ModelMapping},
		{"status_code_mapping", `{"400":"401"}`, channel.StatusCodeMapping}, {"param_override", `{"nested":{"unicode":"測試"}}`, channel.ParamOverride},
		{"header_override", `{"Authorization":"changed-opaque-credential"}`, *channel.HeaderOverride},
		{"channel_info", model.ChannelInfo{MultiKeyPollingIndex: 1}, model.ChannelInfo{}},
	}
	for _, field := range channelFields {
		t.Run("channel/"+field.column, func(t *testing.T) {
			require.NoError(t, model.DB.Model(&model.Channel{}).Where("id = ?", channel.Id).Update(field.column, field.changed).Error)
			assert.NotEqual(t, baseline, read())
			id := channel.Id
			if field.column == "id" {
				id = channel.Id + 100
			}
			require.NoError(t, model.DB.Model(&model.Channel{}).Where("id = ?", id).Update(field.column, field.original).Error)
			assert.Equal(t, baseline, read())
		})
	}
	tokenFields := []struct {
		column            string
		changed, original any
	}{
		{"id", token.Id + 100, token.Id}, {"status", 2, token.Status}, {"name", "changed-token", token.Name}, {"group", "changed-group", token.Group},
		{"expired_time", time.Now().Unix() + 300, token.ExpiredTime}, {"unlimited_quota", true, token.UnlimitedQuota},
		{"model_limits_enabled", true, token.ModelLimitsEnabled}, {"model_limits", "other-model", token.ModelLimits},
		{"cross_group_retry", true, token.CrossGroupRetry}, {"allow_user_quota_query", !token.AllowUserQuotaQuery, token.AllowUserQuotaQuery},
	}
	for _, field := range tokenFields {
		t.Run("token/"+field.column, func(t *testing.T) {
			require.NoError(t, model.DB.Model(&model.Token{}).Where("id = ?", token.Id).Update(field.column, field.changed).Error)
			assert.NotEqual(t, baseline, read())
			id := token.Id
			if field.column == "id" {
				id = token.Id + 100
			}
			require.NoError(t, model.DB.Model(&model.Token{}).Where("id = ?", id).Update(field.column, field.original).Error)
			assert.Equal(t, baseline, read())
		})
	}
	common.OptionMap["OpaqueAllowedOption"] += " changed"
	assert.NotEqual(t, baseline, read())
	common.OptionMap["OpaqueAllowedOption"] = "synthetic-opaque-option"
	common.OptionMap["SecretToken"] = "changed-filtered-secret"
	assert.Equal(t, baseline, read(), "normal filtered secrets are outside the old projection")
	require.NoError(t, model.DB.Model(channel).Update("key", "rotated-key-handled-by-separate-attestation").Error)
	require.NoError(t, model.DB.Model(token).Update("key", "rotated-token-key-not-routing-projection").Error)
	assert.Equal(t, baseline, read(), "credential revision remains the independent per-call attestation's responsibility")
}

func TestLocalOwnerSourceViewRevisionExactOpaqueAndOwnerContract(t *testing.T) {
	t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED", "true")
	oldSecret := common.SessionSecret
	common.SessionSecret = "synthetic-source-view-test-secret"
	t.Cleanup(func() { common.SessionSecret = oldSecret })
	actor := service.AuthIdentity{UserID: 1, SessionID: "synthetic-sid", UserAuthVersion: 1, SessionVersion: 1}
	user := &model.User{Id: 1, Role: 100, Status: 1, Setting: `{"x":1}`}
	options := []*model.Option{{Key: "Z", Value: `{"opaque":"測試"}`}, {Key: "A", Value: "0"}}
	revision, err := localOwnerRoutingRevision(actor, user, nil, nil, options)
	require.NoError(t, err)
	options[0], options[1] = options[1], options[0]
	reordered, err := localOwnerRoutingRevision(actor, user, nil, nil, options)
	require.NoError(t, err)
	assert.Equal(t, revision, reordered)
	for _, field := range []string{"id", "role", "status", "setting"} {
		changed := *user
		switch field {
		case "id":
			changed.Id++
		case "role":
			changed.Role--
		case "status":
			changed.Status++
		case "setting":
			changed.Setting += " "
		}
		other, err := localOwnerRoutingRevision(actor, &changed, nil, nil, options)
		require.NoError(t, err)
		assert.NotEqual(t, revision, other, field)
	}
	for _, field := range []string{"user", "sid", "user-version", "session-version"} {
		changed := actor
		switch field {
		case "user":
			changed.UserID++
		case "sid":
			changed.SessionID += "2"
		case "user-version":
			changed.UserAuthVersion++
		case "session-version":
			changed.SessionVersion++
		}
		other, err := localOwnerRoutingRevision(changed, user, nil, nil, options)
		require.NoError(t, err)
		assert.NotEqual(t, revision, other, field)
	}
	// This is explicitly a domain-separated keyed revision, not an unkeyed
	// confidentiality claim or an authentication/nonce proof.
	key := hmac.New(sha256.New, []byte(common.SessionSecret))
	key.Write([]byte("new-api/owner-local/source-view/key/v1"))
	assert.NotEqual(t, hex.EncodeToString(key.Sum(nil)), revision)
	for _, malformed := range [][]*model.Option{{nil}, {{Key: "A", Value: "0"}, {Key: "A", Value: "1"}}} {
		_, err := localOwnerRoutingRevision(actor, user, nil, nil, malformed)
		assert.Error(t, err)
	}
}

func TestLocalOwnerSourceViewAuthorizationRevocationAndCompleteness(t *testing.T) {
	for _, condition := range []string{"default-off", "anonymous", "ordinary", "pat", "revoked", "expired", "query", "channels-truncated", "tokens-truncated", "revoked-during-read", "role-changed-during-read"} {
		t.Run(condition, func(t *testing.T) {
			router, user, bundle, _, _ := localOwnerSourceFixture(t)
			bearer, path := bundle.AccessToken, "/api/local-owner/source-view"
			switch condition {
			case "default-off":
				t.Setenv("NEW_API_OWNER_LOCAL_SOURCE_VIEW_ENABLED", "false")
			case "anonymous":
				bearer = ""
			case "ordinary":
				require.NoError(t, model.DB.Model(user).Update("role", common.RoleCommonUser).Error)
				require.NoError(t, model.PublishUserAuthCache(user.Id))
			case "pat":
				bearer = model.AccessTokenPrefix + strings.Repeat("p", 43)
				pat := &model.UserAccessToken{Name: "synthetic-source-pat", TokenHash: model.AccessTokenFingerprint(bearer), TokenHint: model.AccessTokenHint(bearer)}
				require.NoError(t, pat.SetScopes([]string{service.AccessTokenScopeOf(authz.ChannelRead), service.AccessTokenScopeOf(authz.ChannelSecretView)}))
				require.NoError(t, model.CreateUserAccessToken(user.Id, pat, service.AccessTokenMaxPerUser))
			case "revoked":
				_, err := model.RevokeUserSession(user.Id, bundle.Session.SID, "synthetic-source-test")
				require.NoError(t, err)
			case "expired":
				require.NoError(t, model.DB.Model(&model.UserSession{}).Where("sid = ?", bundle.Session.SID).Update("expires_at", time.Now().Unix()-1).Error)
			case "query":
				path += "?user_id=999"
			case "channels-truncated":
				for i := range 100 {
					require.NoError(t, model.DB.Create(&model.Channel{Name: "extra-channel-" + strconv.Itoa(i), Key: "unread"}).Error)
				}
			case "tokens-truncated":
				for i := range 100 {
					require.NoError(t, model.DB.Create(&model.Token{UserId: user.Id, Name: "extra-token", Key: "extra-unread-" + strconv.Itoa(i)}).Error)
				}
			case "revoked-during-read", "role-changed-during-read":
				callback := "test:source-view-change-during-read"
				done := false
				require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
					if tx.Statement.Table != "channels" || done {
						return
					}
					done = true
					if condition == "revoked-during-read" {
						_, err := model.RevokeUserSession(user.Id, bundle.Session.SID, "during-source-view")
						require.NoError(t, err)
					} else {
						require.NoError(t, model.DB.Model(user).Update("role", common.RoleCommonUser).Error)
						require.NoError(t, model.PublishUserAuthCache(user.Id))
					}
				}))
				t.Cleanup(func() { model.DB.Callback().Query().Remove(callback) })
			}
			response := localOwnerSourceRequest(router, bearer, path)
			assert.GreaterOrEqual(t, response.Code, 400)
			assert.NotContains(t, response.Body.String(), "routingRevision")
			for _, sensitive := range []string{"synthetic-channel-key", "synthetic-relay-key", "SQL", "sqlite", "SELECT", bundle.RefreshToken} {
				assert.NotContains(t, response.Body.String(), sensitive)
			}
		})
	}
}

func TestLocalOwnerSourceViewOptionsReuseNormalEffectiveFilter(t *testing.T) {
	oldOptions := common.OptionMap
	common.OptionMap = make(map[string]string)
	maps.Copy(common.OptionMap, oldOptions)
	t.Cleanup(func() { common.OptionMap = oldOptions })
	common.OptionMap["SyntheticVisible"] = "opaque-value"
	common.OptionMap["SyntheticSecret"] = "must-not-appear"
	common.OptionMap["theme.frontend"] = "must-not-appear"
	common.OptionMap["billing_setting.billing_mode"] = "ignored-persisted-mode"
	options, err := dashboardOptionSnapshot()
	require.NoError(t, err)
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	GetOptions(c)
	var normal struct {
		Data []*model.Option `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &normal))
	asMap := func(rows []*model.Option) map[string]string {
		result := make(map[string]string)
		for _, row := range rows {
			result[row.Key] = row.Value
		}
		return result
	}
	assert.Equal(t, asMap(normal.Data), asMap(options))
	assert.Equal(t, "opaque-value", asMap(options)["SyntheticVisible"])
	assert.NotContains(t, asMap(options), "SyntheticSecret")
	assert.NotContains(t, asMap(options), "theme.frontend")
	assert.NotEqual(t, "ignored-persisted-mode", asMap(options)["billing_setting.billing_mode"])
}

func TestLocalOwnerSourceViewFreshBindingsDespiteWarmedSessionCache(t *testing.T) {
	router, user, bundle, _, _ := localOwnerSourceFixture(t)
	server := miniredis.RunT(t)
	oldClient, oldEnabled := common.RDB, common.RedisEnabled
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	common.RDB, common.RedisEnabled = client, true
	t.Cleanup(func() { _ = client.Close(); common.RDB, common.RedisEnabled = oldClient, oldEnabled })
	identity, err := service.ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)
	read := func() *httptest.ResponseRecorder {
		return localOwnerSourceRequest(router, bundle.AccessToken, "/api/local-owner/source-view")
	}
	require.Equal(t, http.StatusOK, read().Code)
	changes := []struct {
		field             string
		changed, original any
	}{
		{"version", identity.SessionVersion + 1, identity.SessionVersion},
		{"user_auth_version", identity.UserAuthVersion + 1, identity.UserAuthVersion},
		{"status", "revoked", model.UserSessionStatusActive},
		{"revoked_at", time.Now().Unix(), int64(0)},
		{"expires_at", time.Now().Unix() - 1, bundle.Session.ExpiresAt},
		{"user_id", user.Id + 100, user.Id},
	}
	for _, when := range []string{"before", "during"} {
		for _, change := range changes {
			t.Run(when+"/"+change.field, func(t *testing.T) {
				// Deliberately bypass the normal cache-invalidating mutation API:
				// the direct before/after DB proof must not trust a warmed cache.
				require.Equal(t, http.StatusOK, read().Code)
				if when == "before" {
					require.NoError(t, model.DB.Model(&model.UserSession{}).Where("sid = ?", bundle.Session.SID).Update(change.field, change.changed).Error)
					require.NoError(t, service.ValidateStepUpIdentity(identity), "positive Redis cache deliberately still contains the old valid session")
				} else {
					callback, done := "test:source-view-fresh-binding", false
					require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
						if tx.Statement.Table != "channels" || done {
							return
						}
						done = true
						require.NoError(t, model.DB.Model(&model.UserSession{}).Where("sid = ?", bundle.Session.SID).Update(change.field, change.changed).Error)
						require.NoError(t, service.ValidateStepUpIdentity(identity), "positive Redis cache deliberately still contains the old valid session")
					}))
					defer model.DB.Callback().Query().Remove(callback)
				}
				response := read()
				assert.GreaterOrEqual(t, response.Code, 400)
				assert.NotContains(t, response.Body.String(), "routingRevision")
				require.NoError(t, model.DB.Model(&model.UserSession{}).Where("sid = ?", bundle.Session.SID).Update(change.field, change.original).Error)
			})
		}
	}
	for _, change := range []struct {
		field             string
		changed, original any
	}{
		{"role", common.RoleCommonUser, common.RoleRootUser}, {"status", 2, 1}, {"auth_version", identity.UserAuthVersion + 1, identity.UserAuthVersion},
	} {
		t.Run("user/"+change.field, func(t *testing.T) {
			require.Equal(t, http.StatusOK, read().Code)
			require.NoError(t, model.DB.Model(user).Update(change.field, change.changed).Error)
			response := read()
			assert.GreaterOrEqual(t, response.Code, 400)
			assert.NotContains(t, response.Body.String(), "routingRevision")
			require.NoError(t, model.DB.Model(user).Update(change.field, change.original).Error)
		})
	}
}

func TestLocalOwnerSourceViewRequestContextCancelsReadsAndNeverPublishesRevision(t *testing.T) {
	router, _, bundle, _, _ := localOwnerSourceFixture(t)
	require.Equal(t, http.StatusOK, localOwnerSourceRequest(router, bundle.AccessToken, "/api/local-owner/source-view").Code)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sawChannel, contextMatched, successfulLateQueries := false, true, 0
	before, after := "test:source-view-context-before", "test:source-view-context-after"
	require.NoError(t, model.DB.Callback().Query().Before("gorm:query").Register(before, func(tx *gorm.DB) {
		if tx.Statement.Table == "channels" {
			sawChannel = true
			contextMatched = contextMatched && tx.Statement.Context == ctx
			cancel()
		}
	}))
	require.NoError(t, model.DB.Callback().Query().After("gorm:query").Register(after, func(tx *gorm.DB) {
		if sawChannel && tx.Error == nil {
			successfulLateQueries++
		}
	}))
	t.Cleanup(func() { model.DB.Callback().Query().Remove(before); model.DB.Callback().Query().Remove(after) })
	request := httptest.NewRequest(http.MethodGet, "/api/local-owner/source-view", nil).WithContext(ctx)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Authorization", "Bearer "+bundle.AccessToken)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assert.True(t, sawChannel)
	assert.True(t, contextMatched)
	assert.Zero(t, successfulLateQueries)
	assert.GreaterOrEqual(t, response.Code, 400)
	assert.NotContains(t, response.Body.String(), "routingRevision")
	assert.JSONEq(t, `{"error":"local_owner_source_view_unavailable"}`, response.Body.String())
}

type localOwnerUnreadableBody struct{ reads int }

func (body *localOwnerUnreadableBody) Read([]byte) (int, error) {
	body.reads++
	panic("source-view GET body must not be read")
}
func (*localOwnerUnreadableBody) Close() error { return nil }

func TestLocalOwnerSourceViewRejectsGETBodyWithoutReading(t *testing.T) {
	router, _, bundle, _, _ := localOwnerSourceFixture(t)
	for _, framing := range []string{"unannounced", "positive-length", "unknown-length", "chunked"} {
		t.Run(framing, func(t *testing.T) {
			body := &localOwnerUnreadableBody{}
			request := httptest.NewRequest(http.MethodGet, "/api/local-owner/source-view", nil)
			request.RemoteAddr = "127.0.0.1:12345"
			request.Header.Set("Authorization", "Bearer "+bundle.AccessToken)
			request.Body = body
			switch framing {
			case "positive-length":
				request.ContentLength = 1
			case "unknown-length":
				request.ContentLength = -1
			case "chunked":
				request.TransferEncoding = []string{"chunked"}
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assert.Equal(t, http.StatusBadRequest, response.Code)
			assert.Zero(t, body.reads)
			assert.NotContains(t, response.Body.String(), "routingRevision")
		})
	}
}
