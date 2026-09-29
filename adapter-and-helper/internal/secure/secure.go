// Package secure implements the v5 authentication / encryption layer.
//
// Threat model (see SECURITY.md in the repo root):
//
//   - Anyone on the internet can open a WebSocket to the API Gateway and talk
//     to the cloud function. Every message they send must be rejected unless
//     it proves knowledge of authToken.
//   - Anyone who obtains a YC IAM token + a connection ID can inject frames
//     into the adapter's or a helper's upstream WebSocket via the wsSend API.
//     Every frame a client accepts must therefore be authenticated: control
//     frames by the cloud function (key derived from authToken), stream frames
//     by the peer (key derived from e2eKey, or authToken if e2eKey is unset).
//   - The cloud function / the cloud provider must not be able to read or
//     forge stream payloads when e2eKey is configured (e2eKey is never given
//     to the cloud function).
//
// All constructions use HMAC-SHA256 and AES-256-CTR from the Go standard
// library. The exact byte layouts are mirrored in bridge-cloud/index.js and
// maui-client/Services/Secure.cs; test vectors live in secure_test.go.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Wire constants.
const (
	HelloVersion byte = 0x05
	TagLen            = 16 // truncated HMAC-SHA256 tag length
	IVLen             = 16 // AES-CTR IV length
	HeaderLen         = 9  // [1B type][4B streamID][4B seqID]

	// Directions bound into the peer MAC so a frame can't be reflected back
	// to its sender.
	DirHelperToAdapter byte = 'H'
	DirAdapterToHelper byte = 'A'

	RoleAdapter = "adapter"
	RoleHelper  = "helper"

	// MaxClockSkew bounds how far HELLO / conn-ids timestamps may drift.
	MaxClockSkew = 5 * time.Minute
)

// Keys holds every key derived from the shared secrets.
type Keys struct {
	hello, ticket, ctl, connIDs []byte // from authToken (shared with the cloud function)
	enc, mac                    []byte // from e2eKey (or authToken as fallback)
	E2E                         bool   // true when a separate e2eKey is in use
}

func kdf(secret, label string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("btf5/" + label))
	return m.Sum(nil)
}

func mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// Derive computes all keys. e2eKey may be empty, in which case stream frames
// are still authenticated and encrypted, but with a key the cloud function can
// also derive (it knows authToken).
func Derive(authToken, e2eKey string) *Keys {
	peerSecret := authToken
	if e2eKey != "" {
		peerSecret = e2eKey
	}
	return &Keys{
		hello:   kdf(authToken, "hello"),
		ticket:  kdf(authToken, "ticket"),
		ctl:     kdf(authToken, "ctl"),
		connIDs: kdf(authToken, "connids"),
		enc:     kdf(peerSecret, "peer-enc"),
		mac:     kdf(peerSecret, "peer-mac"),
		E2E:     e2eKey != "",
	}
}

// --- HELLO ---------------------------------------------------------------

// HelloPayload builds a v5 HELLO payload: [ver][8B unix-ms BE][32B HMAC].
// The raw authToken never goes over the wire.
func (k *Keys) HelloPayload(role string, now time.Time) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.UnixMilli()))
	out := make([]byte, 0, 1+8+32)
	out = append(out, HelloVersion)
	out = append(out, ts...)
	out = append(out, mac(k.hello, []byte(role), []byte{0}, ts)...)
	return out
}

// --- Connection ticket (client -> cloud function) -------------------------

// Ticket is appended to every non-HELLO message a client sends on its
// upstream WebSocket. It binds the message to the sender's own connection ID
// (which the API Gateway supplies to the function and which cannot be
// spoofed), so a ticket is useless on any other connection.
func (k *Keys) Ticket(role, connID string) []byte {
	return mac(k.ticket, []byte(role), []byte{0}, []byte(connID))[:TagLen]
}

// --- Control-frame signatures (cloud function -> client) -------------------

// SignCtl appends the cloud-function signature for a frame destined to dest.
// Exposed for tests; the real signer is the cloud function.
func (k *Keys) SignCtl(dest string, frame []byte) []byte {
	t := mac(k.ctl, []byte(dest), []byte{0}, frame)[:TagLen]
	out := make([]byte, 0, len(frame)+TagLen)
	return append(append(out, frame...), t...)
}

// VerifyCtl checks a cloud-function signature for a message received on the
// connection ownConnID and returns the frame without the tag.
func (k *Keys) VerifyCtl(ownConnID string, msg []byte) ([]byte, bool) {
	if len(msg) < HeaderLen+TagLen {
		return nil, false
	}
	frame := msg[:len(msg)-TagLen]
	want := mac(k.ctl, []byte(ownConnID), []byte{0}, frame)[:TagLen]
	if !hmac.Equal(want, msg[len(msg)-TagLen:]) {
		return nil, false
	}
	return frame, true
}

// --- Peer frames (helper <-> adapter) --------------------------------------

// Seal encrypts and authenticates an encoded frame for the peer. The 9-byte
// header stays in clear (the cloud function routes on it in relay mode) but
// is covered by the MAC.
//
//	out = header || iv || AES-256-CTR(enc, iv, payload) || HMAC(mac, dir||header||iv||ct)[:16]
func (k *Keys) Seal(dir byte, frame []byte) ([]byte, error) {
	iv := make([]byte, IVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return k.sealWithIV(dir, frame, iv)
}

func (k *Keys) sealWithIV(dir byte, frame, ivIn []byte) ([]byte, error) {
	if len(frame) < HeaderLen {
		return nil, errors.New("secure: frame too short")
	}
	out := make([]byte, len(frame)+IVLen+TagLen)
	copy(out, frame[:HeaderLen])
	iv := out[HeaderLen : HeaderLen+IVLen]
	copy(iv, ivIn)
	ct := out[HeaderLen+IVLen : len(out)-TagLen]
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, err
	}
	cipher.NewCTR(block, iv).XORKeyStream(ct, frame[HeaderLen:])
	t := mac(k.mac, []byte{dir}, out[:len(out)-TagLen])
	copy(out[len(out)-TagLen:], t[:TagLen])
	return out, nil
}

// Open verifies and decrypts a sealed peer frame and returns the plain
// encoded frame.
func (k *Keys) Open(dir byte, msg []byte) ([]byte, bool) {
	if len(msg) < HeaderLen+IVLen+TagLen {
		return nil, false
	}
	body := msg[:len(msg)-TagLen]
	want := mac(k.mac, []byte{dir}, body)[:TagLen]
	if !hmac.Equal(want, msg[len(msg)-TagLen:]) {
		return nil, false
	}
	iv := body[HeaderLen : HeaderLen+IVLen]
	ct := body[HeaderLen+IVLen:]
	out := make([]byte, HeaderLen+len(ct))
	copy(out, body[:HeaderLen])
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, false
	}
	cipher.NewCTR(block, iv).XORKeyStream(out[HeaderLen:], ct)
	return out, true
}

// --- Adapter /conn-ids endpoint ------------------------------------------

// The request MAC also covers the optional "assign" / "want" parameters (a
// helper connection ID the adapter should allocate a shortId for, and the ID
// that helper already uses), so a MITM can't tamper with them.
func (k *Keys) connIDsReqMAC(ts, assign, want string) string {
	return hex.EncodeToString(mac(k.connIDs, []byte("req"), []byte{0}, []byte(ts), []byte{0}, []byte(assign), []byte{0}, []byte(want)))
}

// ConnIDsAuthHeader builds the Authorization header the cloud function sends.
// Exposed for tests; the real caller is the cloud function.
func (k *Keys) ConnIDsAuthHeader(now time.Time, assign, want string) string {
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	return "BTF5 " + ts + "." + k.connIDsReqMAC(ts, assign, want)
}

// VerifyConnIDsAuth validates the Authorization header (for the given assign
// parameter, "" if absent) and returns its timestamp string (needed to sign
// the response).
func (k *Keys) VerifyConnIDsAuth(header, assign, want string, now time.Time) (string, bool) {
	v, ok := strings.CutPrefix(header, "BTF5 ")
	if !ok {
		return "", false
	}
	ts, sig, ok := strings.Cut(v, ".")
	if !ok {
		return "", false
	}
	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", false
	}
	d := now.Sub(time.UnixMilli(ms))
	if d < -MaxClockSkew || d > MaxClockSkew {
		return "", false
	}
	if !hmac.Equal([]byte(k.connIDsReqMAC(ts, assign, want)), []byte(strings.ToLower(sig))) {
		return "", false
	}
	return ts, true
}

// ConnIDsRespSig signs the response body so the function can trust it even
// over plain HTTP.
func (k *Keys) ConnIDsRespSig(ts string, body []byte) string {
	return hex.EncodeToString(mac(k.connIDs, []byte("resp"), []byte{0}, []byte(ts), []byte{0}, body))
}
