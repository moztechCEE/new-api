package relay

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/relay/channel/codex"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

var codexLocalQuotaHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// codexLocalQuotaReceipt is emitted only from the actual native HTTP error
// path. Unlike the admin snapshot proof it binds the attempted route and the
// selected credential to a typed upstream rejection. It does not claim a billed
// token count, natural exhaustion, or authority to send/learn/customer-write.
func codexLocalQuotaReceipt(c *gin.Context, info *relaycommon.RelayInfo, response *http.Response) string {
	if os.Getenv("NEW_API_OWNER_LOCAL_ATTESTATION_ENABLED") != "true" || c == nil || c.Request == nil || c.Writer.Written() ||
		info == nil || info.ChannelMeta == nil || info.ChannelType != constant.ChannelTypeCodex || info.ChannelId <= 0 || info.ChannelIsMultiKey ||
		info.RelayMode != relayconstant.RelayModeResponses || info.IsModelMapped || info.OriginModelName != info.UpstreamModelName ||
		len(info.ParamOverride) != 0 || len(info.HeadersOverride) != 0 || len(info.RuntimeHeadersOverride) != 0 || info.UseRuntimeHeadersOverride ||
		info.ChannelSetting.Proxy != "" || info.RetryIndex != 0 || service.RequestPolicy(c).Attempts != 1 ||
		(!service.GetChannelConstraints(c).SuppressesRetry() && !service.ShouldSkipRetryAfterChannelAffinityFailure(c)) ||
		info.UsingGroup == "" || info.TokenGroup != info.UsingGroup ||
		response == nil || response.StatusCode != http.StatusTooManyRequests || response.Body == nil || response.Request == nil {
		return ""
	}
	mapping := strings.TrimSpace(c.GetString("status_code_mapping"))
	if mapping != "" && mapping != "{}" {
		return ""
	}
	request := response.Request
	expectedURL, err := (&codex.Adaptor{}).GetRequestURL(info)
	if err != nil || request.Method != http.MethodPost || request.URL == nil || request.URL.String() != expectedURL || request.Response != nil {
		return ""
	}
	var credential service.CodexOAuthKey
	key, ok := service.CodexCredentialProofKey(info.ApiKey)
	if !ok || common.UnmarshalJsonStr(info.ApiKey, &credential) != nil ||
		request.Header.Get("Authorization") != "Bearer "+strings.TrimSpace(credential.AccessToken) ||
		request.Header.Get("chatgpt-account-id") != strings.TrimSpace(credential.AccountID) {
		return ""
	}
	nonce := c.Request.Header.Get(service.CodexLocalQuotaNonceHeader)
	callHash := c.Request.Header.Get(service.CodexLocalQuotaCallHeader)
	inputHash := c.Request.Header.Get(service.CodexLocalQuotaInputHeader)
	schemaHash := c.Request.Header.Get(service.CodexLocalQuotaSchemaHeader)
	if !codexLocalQuotaHash.MatchString(nonce) || !codexLocalQuotaHash.MatchString(callHash) || !codexLocalQuotaHash.MatchString(inputHash) ||
		(schemaHash != "-" && !codexLocalQuotaHash.MatchString(schemaHash)) {
		return ""
	}
	// Inspect a bounded copy and restore the exact stream for the normal error
	// parser, which owns closing it. Neither the raw error nor a prompt is logged.
	body := response.Body
	prefix, readErr := io.ReadAll(io.LimitReader(body, 4097))
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), body), body}
	if readErr != nil || len(prefix) > 4096 {
		return ""
	}
	var failure struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if common.Unmarshal(prefix, &failure) != nil || failure.Error.Type != "usage_limit_reached" {
		return ""
	}
	issuedAt := time.Now().UnixMilli()
	issued := strconv.FormatInt(issuedAt, 10)
	expires := strconv.FormatInt(issuedAt+120000, 10)
	proof := service.CodexProofMAC(key, service.CodexLocalQuotaVersion, nonce, callHash, inputHash, schemaHash,
		request.URL.String(), info.OriginModelName, info.UsingGroup, strconv.Itoa(info.ChannelId), "429", "usage_limit_reached", "1", issued, expires)
	return "v1." + issued + "." + expires + "." + proof
}
