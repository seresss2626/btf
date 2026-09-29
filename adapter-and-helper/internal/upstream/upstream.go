package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/bridge-to-freedom/adapter/internal/config"
	"github.com/bridge-to-freedom/adapter/internal/protocol"
	"github.com/bridge-to-freedom/adapter/internal/secure"
	"github.com/gorilla/websocket"
)

// FrameHandler is called for each decoded frame from the upstream WS.
type FrameHandler func(f protocol.Frame)

// Upstream manages a persistent WebSocket connection to the API Gateway.
type Upstream struct {
	cfg     *config.Config
	handler FrameHandler

	// Security (v5). role is "adapter" or "helper"; peerDir is the direction
	// tag expected on sealed stream frames arriving from the peer.
	role    string
	keys    *secure.Keys
	peerDir byte

	mu        sync.Mutex
	writeMu   sync.Mutex // serializes all WebSocket writes
	conn      *websocket.Conn
	running   bool
	ownConnID string
	ticket    []byte // per-connection auth ticket appended to every upstream write
	iamToken  string

	// Counts dropped unauthenticated inbound messages (logged sparsely).
	rejected uint64

	// Helper-side state (single adapter peer).
	peerConnID    string
	staleConnID   string // last peer ID that failed wsSend
	helperShortID byte   // own short ID assigned by cloud function (helper only; 0 on adapter)

	// Adapter-side state (multiple helper peers).
	helpers     map[byte]string // shortID -> helper connID
	helperStale map[byte]string // shortID -> last failed connID (rejects stale PEER_CONN)
}

// New creates an upstream. role is secure.RoleAdapter or secure.RoleHelper.
func New(cfg *config.Config, role string, keys *secure.Keys, handler FrameHandler) *Upstream {
	peerDir := secure.DirAdapterToHelper
	if role == secure.RoleAdapter {
		peerDir = secure.DirHelperToAdapter
	}
	return &Upstream{
		cfg:         cfg,
		handler:     handler,
		role:        role,
		keys:        keys,
		peerDir:     peerDir,
		helpers:     make(map[byte]string),
		helperStale: make(map[byte]string),
	}
}

// writeWithTicket appends this connection's auth ticket and writes one binary
// message. Every upstream write except HELLO must go through here: the cloud
// function drops any message without a valid ticket.
func (u *Upstream) writeWithTicket(c *websocket.Conn, data []byte) error {
	u.mu.Lock()
	t := u.ticket
	u.mu.Unlock()
	if t == nil {
		return fmt.Errorf("upstream not authenticated")
	}
	msg := make([]byte, 0, len(data)+len(t))
	msg = append(append(msg, data...), t...)
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	return c.WriteMessage(websocket.BinaryMessage, msg)
}

// writeTimeout bounds a single upstream write so a stalled socket can't wedge
// every sender (all writes share writeMu).
const writeTimeout = 15 * time.Second

// verifyInbound authenticates one message from the upstream WS and returns
// the plain frame. Control frames (streamID 0) must be signed by the cloud
// function; stream frames must be sealed by the peer, except OPEN_FAIL/RST
// synthesised by the cloud function in relay mode (signed like control).
func (u *Upstream) verifyInbound(msg []byte) (protocol.Frame, bool) {
	if len(msg) < secure.HeaderLen {
		return protocol.Frame{}, false
	}
	u.mu.Lock()
	own := u.ownConnID
	u.mu.Unlock()

	streamID := binary.BigEndian.Uint32(msg[1:5])
	if streamID != 0 {
		if plain, ok := u.keys.Open(u.peerDir, msg); ok {
			f, err := protocol.Decode(plain)
			return f, err == nil
		}
		if msg[0] != protocol.MsgOpenFail && msg[0] != protocol.MsgRst {
			return protocol.Frame{}, false
		}
	}
	frame, ok := u.keys.VerifyCtl(own, msg)
	if !ok {
		return protocol.Frame{}, false
	}
	f, err := protocol.Decode(frame)
	return f, err == nil
}

// OwnConnID returns this side's upstream connection ID.
func (u *Upstream) OwnConnID() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ownConnID
}

// PeerConnID returns the peer's upstream connection ID.
func (u *Upstream) PeerConnID() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peerConnID
}

// SetPeerConnID updates the peer connection ID (from PEER_CONN).
func (u *Upstream) SetPeerConnID(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.peerConnID = id
}

// IAMToken returns the current IAM token.
func (u *Upstream) IAMToken() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.iamToken
}

// SetIAMToken updates the IAM token (from PONG or PEER_CONN).
func (u *Upstream) SetIAMToken(token string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.iamToken = token
}

// Send writes a binary frame to the upstream WS. Thread-safe.
func (u *Upstream) Send(data []byte) error {
	u.mu.Lock()
	c := u.conn
	u.mu.Unlock()
	if c == nil {
		return fmt.Errorf("upstream not connected")
	}
	return u.writeWithTicket(c, data)
}

// SendSync sends a SYNC frame through the upstream WS.
func (u *Upstream) SendSync() error {
	return u.Send(u.claimFrame(protocol.MsgSync))
}

// claimFrame builds a PING/SYNC frame carrying our helper short ID claim
// (empty payload on the adapter).
func (u *Upstream) claimFrame(t byte) []byte {
	return protocol.Encode(protocol.Frame{Type: t, Payload: protocol.EncodeClaim(u.HelperShortID())})
}

// MarkPeerStale clears the peer connection ID and triggers a SYNC, but only if
// the current peer still matches expectedConnID. This compare-and-clear stops a
// slow/old failed request from evicting a peer that has since reconnected under
// a new connID. Call this only for a definitive "connection not found" failure.
func (u *Upstream) MarkPeerStale(expectedConnID string) {
	u.mu.Lock()
	old := u.peerConnID
	if old == "" || (expectedConnID != "" && old != expectedConnID) {
		u.mu.Unlock()
		return
	}
	u.peerConnID = ""
	u.staleConnID = old
	u.mu.Unlock()
	log.Printf("[WARN] peer connId %s marked stale, sending SYNC", old)
	if err := u.SendSync(); err != nil {
		log.Printf("[WARN] SYNC send failed: %v", err)
	}
}

// IsStaleConnID returns true if the given ID was the last one marked stale.
// Used to reject PEER_CONN with the same broken ID.
func (u *Upstream) IsStaleConnID(id string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return id != "" && id == u.staleConnID
}

// ClearStaleConnID clears the stale ID tracking (call when a new valid peer connects).
func (u *Upstream) ClearStaleConnID() {
	u.mu.Lock()
	u.staleConnID = ""
	u.mu.Unlock()
}

// --- Adapter-side multi-helper API ---

// HelperShortID returns this helper's assigned short ID (helper-side only).
// Returns 0 on the adapter or when no ID has been assigned yet.
func (u *Upstream) HelperShortID() byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.helperShortID
}

// SetHelperShortID stores this helper's assigned short ID (helper-side only).
func (u *Upstream) SetHelperShortID(id byte) {
	u.mu.Lock()
	u.helperShortID = id
	u.mu.Unlock()
}

// Helper returns a helper's connID by short ID (adapter-side). Empty if unknown.
func (u *Upstream) Helper(shortID byte) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.helpers[shortID]
}

// SetHelper records a helper's connID under its short ID (adapter-side).
func (u *Upstream) SetHelper(shortID byte, connID string) {
	u.mu.Lock()
	// One connection has exactly one short ID: drop older slots for it.
	for sid, cid := range u.helpers {
		if cid == connID && sid != shortID {
			delete(u.helpers, sid)
		}
	}
	u.helpers[shortID] = connID
	// A fresh announcement clears any prior staleness for this slot.
	delete(u.helperStale, shortID)
	u.mu.Unlock()
}

// AssignHelper returns the short ID for a helper connection (adapter-side).
// The adapter is the single authority for short IDs: serverless function
// instances don't share memory and used to hand out colliding IDs. A known
// helper keeps its ID; a new one gets `want` (the ID it already stamps into
// its streams) if that is free, otherwise the lowest free ID. Returns 0 if all
// 255 are in use.
func (u *Upstream) AssignHelper(connID string, want byte) byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	for sid, cid := range u.helpers {
		if cid == connID {
			return sid
		}
	}
	if _, used := u.helpers[want]; want != 0 && !used {
		u.helpers[want] = connID
		delete(u.helperStale, want)
		return want
	}
	for sid := 1; sid <= 255; sid++ {
		if _, used := u.helpers[byte(sid)]; !used {
			u.helpers[byte(sid)] = connID
			delete(u.helperStale, byte(sid))
			return byte(sid)
		}
	}
	return 0
}

// RemoveHelper drops a helper by short ID (adapter-side). Returns the removed
// connID (or "" if there was no such helper).
func (u *Upstream) RemoveHelper(shortID byte) string {
	u.mu.Lock()
	old := u.helpers[shortID]
	delete(u.helpers, shortID)
	delete(u.helperStale, shortID)
	u.mu.Unlock()
	return old
}

// Helpers returns a snapshot of all known helpers (adapter-side).
func (u *Upstream) Helpers() map[byte]string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make(map[byte]string, len(u.helpers))
	for k, v := range u.helpers {
		out[k] = v
	}
	return out
}

// HasHelpers reports whether at least one helper is connected (adapter-side).
func (u *Upstream) HasHelpers() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.helpers) > 0
}

// MarkHelperStale removes a helper that has stopped responding to wsSend, but
// only if it still maps to expectedConnID. This compare-and-clear prevents a
// slow/old failed request from evicting a helper that has since reconnected
// under a new connID. Call this only for a definitive "connection not found"
// failure. Returns the removed connID (or "" if nothing was removed).
func (u *Upstream) MarkHelperStale(shortID byte, expectedConnID string) string {
	u.mu.Lock()
	old := u.helpers[shortID]
	if old == "" || (expectedConnID != "" && old != expectedConnID) {
		u.mu.Unlock()
		return ""
	}
	delete(u.helpers, shortID)
	u.helperStale[shortID] = old
	u.mu.Unlock()
	log.Printf("[WARN] helper shortID=%d connID=%s marked stale", shortID, old)
	return old
}

// IsHelperStale checks whether the given (shortID, connID) pair matches the
// most recent stale entry. Used to ignore PEER_CONN echoes carrying a broken ID.
func (u *Upstream) IsHelperStale(shortID byte, connID string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return connID != "" && u.helperStale[shortID] == connID
}

// HasAnyPeer reports whether the upstream has at least one known peer:
// for a helper that's a non-empty peerConnID, for an adapter it's any helper.
func (u *Upstream) HasAnyPeer() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peerConnID != "" || len(u.helpers) > 0
}

func (u *Upstream) dial(ctx context.Context) (*websocket.Conn, error) {
	log.Printf("[INFO] connecting to %s ...", u.cfg.Bridge.URL)
	dialer := websocket.Dialer{
		EnableCompression: false,
		HandshakeTimeout:  10 * time.Second,
	}
	ws, httpResp, err := dialer.DialContext(ctx, u.cfg.Bridge.URL, nil)
	if err != nil {
		if httpResp != nil {
			log.Printf("[WARN] dial failed: %v (HTTP status %d)", err, httpResp.StatusCode)
		}
		return nil, err
	}
	log.Printf("[INFO] WebSocket connected, sending HELLO...")

	// HELLO (v5): proves knowledge of authToken without sending it.
	hello := protocol.Encode(protocol.Frame{
		Type:    protocol.MsgHello,
		Payload: u.keys.HelloPayload(u.role, time.Now()),
	})
	ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := ws.WriteMessage(websocket.BinaryMessage, hello); err != nil {
		ws.Close()
		return nil, fmt.Errorf("send HELLO: %w", err)
	}

	// Wait for HELLO_OK / HELLO_ERR. Other frames (e.g. a PEER_CONN pushed
	// by another function invocation that already learned our connection ID)
	// can overtake the HELLO response; skip them instead of failing.
	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	var msg []byte
	for {
		_, m, err := ws.ReadMessage()
		if err != nil {
			ws.Close()
			return nil, fmt.Errorf("read HELLO response (timeout?): %w", err)
		}
		if len(m) >= 1 && m[0] == protocol.MsgHelloErr {
			ws.Close()
			reason := "auth failed"
			if len(m) > secure.HeaderLen {
				reason = string(m[secure.HeaderLen:])
			}
			return nil, fmt.Errorf("rejected by cloud function: %q (authToken mismatch, clock skew > %v, or outdated cloud function)", reason, secure.MaxClockSkew)
		}
		if len(m) >= secure.HeaderLen+secure.TagLen && m[0] == protocol.MsgHelloOK {
			msg = m
			break
		}
		log.Printf("[DEBUG] skipping frame type=0x%02x while waiting for HELLO_OK", m[0])
	}
	ws.SetReadDeadline(time.Time{}) // clear deadline
	// The signature is bound to our own connection ID, which is inside the
	// (not yet verified) payload: decode first, then verify with it.
	resp, err := protocol.Decode(msg[:len(msg)-secure.TagLen])
	if err != nil {
		ws.Close()
		return nil, err
	}
	ownID, peerID, iamToken, helperShortID, err := protocol.DecodeHelloOK(resp.Payload)
	if err != nil {
		ws.Close()
		return nil, fmt.Errorf("decode HELLO_OK: %w", err)
	}
	if _, ok := u.keys.VerifyCtl(ownID, msg); !ok {
		ws.Close()
		return nil, fmt.Errorf("HELLO_OK signature invalid (authToken mismatch or forged response)")
	}

	u.mu.Lock()
	u.ownConnID = ownID
	u.ticket = u.keys.Ticket(u.role, ownID)
	u.peerConnID = peerID
	u.iamToken = iamToken
	u.helperShortID = helperShortID // 0 on adapter, 1..255 on helper
	u.mu.Unlock()

	if helperShortID != 0 {
		log.Printf("[INFO] upstream authenticated ownID=%s peerID=%s helperShortID=%d", ownID, peerID, helperShortID)
	} else {
		log.Printf("[INFO] upstream authenticated ownID=%s peerID=%s", ownID, peerID)
	}

	if tc, ok := ws.UnderlyingConn().(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	return ws, nil
}

func (u *Upstream) readLoop(ctx context.Context) {
	if pi := u.cfg.PingInterval(); pi > 0 {
		go u.pingLoop(ctx, pi)
	}
	for {
		msgType, msg, err := u.conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[WARN] upstream read error: %v", err)
			return
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		f, ok := u.verifyInbound(msg)
		if !ok {
			u.rejected++
			// Log the first few and then sparsely: a flood of forged frames
			// must not turn into a flood of log lines.
			if u.rejected <= 5 || u.rejected%1000 == 0 {
				log.Printf("[WARN] dropped unauthenticated upstream message (len=%d, total dropped=%d) — forged frame, or authToken/e2eKey mismatch between components", len(msg), u.rejected)
			}
			continue
		}
		u.handler(f)
	}
}

func (u *Upstream) pingLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.mu.Lock()
			c := u.conn
			hasPeer := u.peerConnID != "" || len(u.helpers) > 0
			u.mu.Unlock()
			if c == nil {
				continue
			}
			// Only ping while at least one peer is known. Without a peer, we
			// don't need IAM-token freshness (no wsSend target) and we don't
			// need to keep the cloud function warm. The WS itself is allowed
			// to idle out; if APIGW drops it, Run() will reconnect on demand
			// and the function's HTTP poke on next helper CONNECT handles
			// discovery.
			if !hasPeer {
				log.Printf("[DEBUG] ping skipped: no peer")
				continue
			}
			log.Printf("[DEBUG] sending PING")
			if err := u.writeWithTicket(c, u.claimFrame(protocol.MsgPing)); err != nil {
				log.Printf("[WARN] PING send failed: %v", err)
			}
		}
	}
}

// reconnectPause is the minimum delay between an upstream disconnect and the
// next reconnect attempt. dial() only applies exponential backoff on connect
// *failure*; this guards the success-then-immediate-drop case so a flapping
// upstream can't hammer the API Gateway in a tight loop. Derived from the
// configured initial backoff, with a floor so a missing/zero config can't
// produce a busy loop.
func (u *Upstream) reconnectPause() time.Duration {
	d := u.cfg.InitialDelay()
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// Run connects and reconnects in a loop until ctx is cancelled.
func (u *Upstream) Run(ctx context.Context) {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return
	}
	u.running = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.running = false
		u.mu.Unlock()
	}()

	delay := u.cfg.InitialDelay()
	for {
		if ctx.Err() != nil {
			return
		}
		ws, err := u.dial(ctx)
		if err != nil {
			log.Printf("[WARN] connect failed: %v retryIn=%v", err, delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			next := time.Duration(float64(delay) * u.cfg.Bridge.Reconnect.BackoffMultiplier)
			if next > u.cfg.MaxDelay() {
				next = u.cfg.MaxDelay()
			}
			delay = next
			continue
		}
		delay = u.cfg.InitialDelay()

		u.mu.Lock()
		u.conn = ws
		u.mu.Unlock()
		log.Println("[INFO] upstream connected")

		// Send an immediate PING to force the cloud function to cross-notify
		// the peer of our connId. Without this, discovery depends on the
		// periodic PING (30s default) and the peer may time out waiting.
		if err := u.writeWithTicket(ws, u.claimFrame(protocol.MsgPing)); err != nil {
			log.Printf("[WARN] initial PING failed: %v", err)
		} else {
			log.Println("[DEBUG] sent initial PING for fast discovery")
		}

		// Proactive SYNC: if HELLO_OK didn't include a peer ID, ask the cloud
		// function for it right away. The initial PING above tells the cloud to
		// notify the OTHER side about us; SYNC asks the cloud to tell US about
		// the other side. Without this, our local peerConnID stays empty until
		// the next periodic ping/sync cycle (~30s) or until the first incoming
		// TCP connection triggers waitForPeer(). With it, peer is typically
		// known after one round-trip (~200ms).
		//
		// Skip entirely in relay mode: there the data path is the upstream WS
		// (the cloud relays to the adapter), so we never need peerConnID. Worse,
		// a cold cloud instance may answer this SYNC with PEER_GONE, which the
		// helper would otherwise act on — a self-inflicted teardown during
		// startup. No SYNC, no spurious PEER_GONE.
		u.mu.Lock()
		needSync := u.peerConnID == "" && !u.cfg.WsAPI.Relay
		u.mu.Unlock()
		if needSync {
			if err := u.writeWithTicket(ws, u.claimFrame(protocol.MsgSync)); err == nil {
				log.Println("[DEBUG] HELLO_OK had no peer; sent proactive SYNC")
			}
		}

		readCtx, readCancel := context.WithCancel(ctx)
		captured := ws
		go func() {
			<-readCtx.Done()
			// Try graceful WS close, then force-close quickly
			closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shutdown")
			captured.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(500*time.Millisecond))
			time.Sleep(200 * time.Millisecond)
			captured.Close()
		}()

		u.readLoop(readCtx)
		readCancel()

		u.mu.Lock()
		u.conn = nil
		u.ownConnID = ""
		u.ticket = nil
		u.peerConnID = ""
		u.iamToken = ""
		u.helperShortID = 0
		// Drop the adapter-side helper table on reconnect; the cloud function
		// will re-announce surviving helpers via PEER_CONN on its next pass.
		u.helpers = make(map[byte]string)
		u.helperStale = make(map[byte]string)
		u.mu.Unlock()

		if ctx.Err() != nil {
			log.Println("[INFO] upstream shut down")
			return
		}
		log.Println("[INFO] upstream disconnected, reconnecting...")
		// Minimum pause before reconnecting so a connection that drops right
		// after a successful handshake isn't retried instantly.
		select {
		case <-ctx.Done():
			log.Println("[INFO] upstream shut down")
			return
		case <-time.After(u.reconnectPause()):
		}
	}
}
