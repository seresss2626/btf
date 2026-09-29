package secure

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"
)

// Cross-language test vectors. The same file is checked by the cloud
// function (bridge-cloud/test/vectors.test.js) and the MAUI client
// (maui-client-tests). Regenerate with:
//
//	go test ./internal/secure -run TestVectors -update
var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "../../../testdata/vectors.json"

type vectors struct {
	AuthToken         string `json:"authToken"`
	E2EKey            string `json:"e2eKey"`
	TsMs              int64  `json:"tsMs"`
	HelloHelper       string `json:"helloHelper"`
	HelloAdapt        string `json:"helloAdapter"`
	TicketConn        string `json:"ticketConnId"`
	TicketHelp        string `json:"ticketHelper"`
	CtlDest           string `json:"ctlDest"`
	CtlFrame          string `json:"ctlFrame"`
	CtlSigned         string `json:"ctlSigned"`
	PeerFrame         string `json:"peerFrame"`
	PeerIV            string `json:"peerIv"`
	PeerSealedH       string `json:"peerSealedH"`
	PeerSealedA       string `json:"peerSealedA"`
	PeerSealedNoE2E   string `json:"peerSealedNoE2E"`
	ConnIDsAuth       string `json:"connIdsAuth"`
	ConnIDsAuthAssign string `json:"connIdsAuthAssign"`
	ConnIDsBody       string `json:"connIdsBody"`
	ConnIDsSig        string `json:"connIdsSig"`
}

func build(t *testing.T) vectors {
	const tok = "test-auth-token-0123456789abcdef"
	const e2e = "test-e2e-key-fedcba9876543210"
	ts := time.UnixMilli(1790000000000)
	k := Derive(tok, e2e)
	k0 := Derive(tok, "")
	frame := []byte{0x20, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07}
	frame = append(frame, []byte("hello, world! this payload spans more than one AES block....")...)
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0dfffe") // exercises counter carry
	sH, err := k.sealWithIV(DirHelperToAdapter, frame, iv)
	if err != nil {
		t.Fatal(err)
	}
	sA, _ := k.sealWithIV(DirAdapterToHelper, frame, iv)
	s0, _ := k0.sealWithIV(DirHelperToAdapter, frame, iv)
	ctl := []byte{0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x03, 'a', 'b', 'c', 0x00, 0x00}
	body := []byte(`{"adapterConnId":"A1","helpers":[{"shortId":1,"connId":"H1"}]}`)
	auth := k.ConnIDsAuthHeader(ts, "", "")
	authAssign := k.ConnIDsAuthHeader(ts, "helper-conn-7", "3")
	return vectors{
		AuthToken:         tok,
		E2EKey:            e2e,
		TsMs:              ts.UnixMilli(),
		HelloHelper:       hex.EncodeToString(k.HelloPayload(RoleHelper, ts)),
		HelloAdapt:        hex.EncodeToString(k.HelloPayload(RoleAdapter, ts)),
		TicketConn:        "d0conn-ticket-test",
		TicketHelp:        hex.EncodeToString(k.Ticket(RoleHelper, "d0conn-ticket-test")),
		CtlDest:           "dest-conn-1",
		CtlFrame:          hex.EncodeToString(ctl),
		CtlSigned:         hex.EncodeToString(k.SignCtl("dest-conn-1", ctl)),
		PeerFrame:         hex.EncodeToString(frame),
		PeerIV:            hex.EncodeToString(iv),
		PeerSealedH:       hex.EncodeToString(sH),
		PeerSealedA:       hex.EncodeToString(sA),
		PeerSealedNoE2E:   hex.EncodeToString(s0),
		ConnIDsAuth:       auth,
		ConnIDsAuthAssign: authAssign,
		ConnIDsBody:       string(body),
		ConnIDsSig:        k.ConnIDsRespSig("1790000000000", body),
	}
}

func TestVectors(t *testing.T) {
	v := build(t)
	if *update {
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var want vectors
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if want != v {
		t.Fatalf("vectors changed; the wire format must stay in sync with JS/C# (run with -update only if intentional)")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := Derive("auth-token-aaaaaaaaaaaa", "e2e-key-bbbbbbbbbbbbbbbb")
	for _, n := range []int{0, 1, 15, 16, 17, 1000, 32 * 1024} {
		frame := make([]byte, HeaderLen+n)
		frame[0] = 0x20
		for i := range frame[HeaderLen:] {
			frame[HeaderLen+i] = byte(i)
		}
		s, err := k.Seal(DirHelperToAdapter, frame)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && bytes.Contains(s, frame[HeaderLen:]) && n >= 16 {
			t.Fatalf("payload visible in sealed frame")
		}
		p, ok := k.Open(DirHelperToAdapter, s)
		if !ok || !bytes.Equal(p, frame) {
			t.Fatalf("round trip failed n=%d", n)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	k := Derive("auth-token-aaaaaaaaaaaa", "e2e-key-bbbbbbbbbbbbbbbb")
	frame := append([]byte{0x10, 0, 0, 0, 1, 0, 0, 0, 1}, []byte("data")...)
	s, _ := k.Seal(DirHelperToAdapter, frame)

	if _, ok := k.Open(DirAdapterToHelper, s); ok {
		t.Fatal("accepted reflected frame (wrong direction)")
	}
	for i := range s {
		m := bytes.Clone(s)
		m[i] ^= 0x01
		if _, ok := k.Open(DirHelperToAdapter, m); ok {
			t.Fatalf("accepted tampered frame (byte %d)", i)
		}
	}
	other := Derive("auth-token-aaaaaaaaaaaa", "different-e2e-key-cccccccc")
	if _, ok := other.Open(DirHelperToAdapter, s); ok {
		t.Fatal("accepted frame under a different e2eKey")
	}
	// Plain (legacy v4) frame must be rejected.
	if _, ok := k.Open(DirHelperToAdapter, append(frame, make([]byte, 32)...)); ok {
		t.Fatal("accepted unsealed frame")
	}
}

func TestCtl(t *testing.T) {
	k := Derive("auth-token-aaaaaaaaaaaa", "")
	f := []byte{0x05, 0, 0, 0, 0, 0, 0, 0, 0}
	s := k.SignCtl("conn-A", f)
	if got, ok := k.VerifyCtl("conn-A", s); !ok || !bytes.Equal(got, f) {
		t.Fatal("valid ctl rejected")
	}
	if _, ok := k.VerifyCtl("conn-B", s); ok {
		t.Fatal("ctl for another connection accepted")
	}
	if _, ok := Derive("another-token-xxxxxxx", "").VerifyCtl("conn-A", s); ok {
		t.Fatal("ctl under another authToken accepted")
	}
}

func TestConnIDsAuth(t *testing.T) {
	k := Derive("auth-token-aaaaaaaaaaaa", "")
	now := time.Now()
	h := k.ConnIDsAuthHeader(now, "", "")
	if _, ok := k.VerifyConnIDsAuth(h, "", "", now); !ok {
		t.Fatal("valid header rejected")
	}
	if _, ok := k.VerifyConnIDsAuth(h, "", "", now.Add(MaxClockSkew+time.Second)); ok {
		t.Fatal("stale header accepted")
	}
	if _, ok := k.VerifyConnIDsAuth("Bearer auth-token-aaaaaaaaaaaa", "", "", now); ok {
		t.Fatal("legacy bearer accepted")
	}
	if _, ok := k.VerifyConnIDsAuth("", "", "", now); ok {
		t.Fatal("empty header accepted")
	}
	if _, ok := k.VerifyConnIDsAuth(h, "", "7", now); ok {
		t.Fatal("header accepted with a different want parameter")
	}
	if _, ok := k.VerifyConnIDsAuth(h, "some-helper", "", now); ok {
		t.Fatal("header accepted with a different assign parameter")
	}
	if _, ok := Derive("another-token-xxxxxxx", "").VerifyConnIDsAuth(h, "", "", now); ok {
		t.Fatal("header under another token accepted")
	}
}
