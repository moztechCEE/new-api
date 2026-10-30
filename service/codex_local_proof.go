package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"github.com/QuantumNous/new-api/common"
)

const (
	CodexLocalQuotaNonceHeader  = "X-New-Api-Local-Codex-Nonce"
	CodexLocalQuotaCallHeader   = "X-New-Api-Local-Codex-Call-Sha256"
	CodexLocalQuotaInputHeader  = "X-New-Api-Local-Codex-Input-Sha256"
	CodexLocalQuotaSchemaHeader = "X-New-Api-Local-Codex-Schema-Sha256"
	CodexLocalQuotaHeader       = "X-New-Api-Local-Codex-Quota"
	CodexLocalQuotaVersion      = "new-api.local-codex-quota.v1"
)

// CodexCredentialProofKey binds the four actual, freshly bootstrapped fields.
// It is shared by non-secret local snapshot and data-plane outcome proofs;
// neither proof is a login grant, raw credential disclosure or billing receipt.
func CodexCredentialProofKey(raw string) ([32]byte, bool) {
	var credential CodexOAuthKey
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
	writeCodexProofParts(digest, values...)
	var key [32]byte
	copy(key[:], digest.Sum(nil))
	return key, true
}

func CodexProofMAC(key [32]byte, parts ...string) string {
	mac := hmac.New(sha256.New, key[:])
	writeCodexProofParts(mac, parts...)
	return hex.EncodeToString(mac.Sum(nil))
}

func writeCodexProofParts(digest hash.Hash, parts ...string) {
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(part))
	}
}
