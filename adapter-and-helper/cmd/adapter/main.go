package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bridge-to-freedom/adapter/internal/config"
	"github.com/bridge-to-freedom/adapter/internal/protocol"
	"github.com/bridge-to-freedom/adapter/internal/secure"
	"github.com/bridge-to-freedom/adapter/internal/streams"
	"github.com/bridge-to-freedom/adapter/internal/upstream"
	"github.com/bridge-to-freedom/adapter/internal/wsapi"
)

func main() {
	cfgPath := "adapter.config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags)

	// Validate secrets and required settings (the HTTP recovery endpoint is
	// required: the cloud function polls it on cold start).
	warnings, err := cfg.Validate(secure.RoleAdapter)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	for _, w := range warnings {
		log.Printf("[WARN] %s", w)
	}
	keys := secure.Derive(cfg.Bridge.AuthToken, cfg.Bridge.E2EKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wsClient := wsapi.NewClient()

	var ups *upstream.Upstream
	var sm *streams.Manager

	sm = streams.NewManager(func(data []byte) error {
		// Frame on the wire is [1B type][4B streamID BE][4B seqID BE][payload].
		// The top byte of streamID is the helper short ID assigned by the cloud
		// function; we use it to route per-stream frames back to the originating
		// helper without having to decode the whole frame.
		var shortID byte
		if len(data) >= 2 {
			shortID = data[1]
		}
		peerID := ups.Helper(shortID)
		token := ups.IAMToken()
		if peerID == "" || token == "" {
			return fmt.Errorf("no helper for shortID=%d", shortID)
		}
		sealed, err := keys.Seal(secure.DirAdapterToHelper, data)
		if err != nil {
			return err
		}
		err = wsClient.Send(peerID, sealed, "BINARY", token)
		if err != nil {
			if wsapi.IsConnectionNotFound(err) {
				// Definitive: this helper's connection is gone. Drop just this
				// helper (compare-and-clear against the connID we sent to, so a
				// helper that reconnected under a new connID isn't evicted);
				// other helpers keep working.
				if old := ups.MarkHelperStale(shortID, peerID); old != "" {
					n := sm.CloseHelper(shortID)
					log.Printf("[WARN] helper shortID=%d gone (connId=%s not found), closed %d streams: %v", shortID, old, n, err)
				}
			} else {
				// Transient (timeout, rate limit, server error): keep the helper
				// ID so a healthy peer isn't poisoned by a blip. The affected
				// stream still sees the error and recovers on its own.
				log.Printf("[WARN] helper shortID=%d transient wsSend error (keeping peer): %v", shortID, err)
			}
		}
		return err
	})
	sm.CoalesceDelay = cfg.CoalesceDelay()
	sm.Reorder = true

	ups = upstream.New(cfg, secure.RoleAdapter, keys, func(f protocol.Frame) {
		switch f.Type {
		// --- Control ---
		case protocol.MsgPeerConn:
			peerID, iamToken, helperShortID, err := protocol.DecodePeerConn(f.Payload)
			if err != nil {
				log.Printf("[WARN] bad PEER_CONN: %v", err)
				return
			}
			if helperShortID == 0 {
				// Legacy / cloud function without multi-helper support. Treat
				// as helper shortID=1 so a single helper still works.
				helperShortID = 1
			}
			if ups.IsHelperStale(helperShortID, peerID) {
				log.Printf("[WARN] PEER_CONN with stale ID shortID=%d peerID=%s, ignoring", helperShortID, peerID)
				return
			}
			log.Printf("[INFO] PEER_CONN received: shortID=%d peerID=%s tokenLen=%d", helperShortID, peerID, len(iamToken))
			ups.SetHelper(helperShortID, peerID)
			if iamToken != "" {
				ups.SetIAMToken(iamToken)
			}
		case protocol.MsgPeerGone:
			shortID := protocol.DecodePeerGone(f.Payload)
			if shortID == 0 {
				// Legacy / all-peers-gone (e.g. cloud function couldn't tell us
				// which). Close everything.
				log.Printf("[INFO] PEER_GONE (all) received, closing %d streams", sm.Count())
				// Clear every helper slot.
				for sid := range ups.Helpers() {
					ups.RemoveHelper(sid)
				}
				sm.CloseAll()
			} else {
				old := ups.RemoveHelper(shortID)
				n := sm.CloseHelper(shortID)
				log.Printf("[INFO] PEER_GONE received: shortID=%d peerID=%s closed=%d streams", shortID, old, n)
			}
		case protocol.MsgPong:
			iamToken, _, err := protocol.DecodePong(f.Payload)
			if err != nil {
				log.Printf("[WARN] bad PONG: %v", err)
				return
			}
			log.Printf("[DEBUG] PONG received, tokenLen=%d", len(iamToken))
			ups.SetIAMToken(iamToken)
		case protocol.MsgPing:
			// We never answer PINGs (only the cloud function does). A stray PING
			// can still reach us if an older cloud function relays the peer's
			// keepalive instead of handling it; ignore it quietly instead of
			// logging it as an unknown frame.
			log.Printf("[DEBUG] ignoring stray PING")

		// --- Stream ---
		case protocol.MsgOpen, protocol.MsgData, protocol.MsgFin, protocol.MsgRst:
			if f.Type != protocol.MsgData {
				log.Printf("[INFO] %s received stream=%d seq=%d",
					map[byte]string{protocol.MsgOpen: "OPEN", protocol.MsgFin: "FIN", protocol.MsgRst: "RST"}[f.Type],
					f.StreamID, f.SeqID)
			}
			// Probe streams are entirely synthetic on the adapter side: we never
			// register a Stream, never dial a target, and we don't care about
			// in-order delivery of the helper's GET/FIN — so skip the reorder
			// machinery (which would otherwise leak a buffer entry per probe).
			if protocol.IsProbe(f.StreamID) {
				if f.Type == protocol.MsgOpen {
					go handleProbe(sm, f.StreamID)
				}
				// DATA/FIN/RST from the helper for this probe are silently absorbed.
				return
			}
			sm.HandleStreamFrame(f, func(of protocol.Frame) {
				switch of.Type {
				case protocol.MsgOpen:
					go handleOpen(cfg, sm, of.StreamID)
				case protocol.MsgData:
					sm.HandleData(of.StreamID, of.Payload)
				case protocol.MsgFin:
					sm.HandleFin(of.StreamID)
				case protocol.MsgRst:
					sm.HandleRst(of.StreamID)
				}
			})
		default:
			log.Printf("[WARN] unknown frame type=0x%02x stream=%d", f.Type, f.StreamID)
		}
	})

	// Signal handling
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("[INFO] shutting down")
		// Hard exit deadline — if graceful shutdown takes too long, force exit
		go func() {
			time.Sleep(3 * time.Second)
			log.Println("[WARN] graceful shutdown timed out, forcing exit")
			os.Exit(1)
		}()
		sm.CloseAll()
		cancel()
	}()

	// HTTP server for the conn-ids endpoint (path configurable via http.path).
	// Required — the cloud function calls it on cold start to recover state.
	{
		httpPath := cfg.HTTP.Path
		if httpPath == "" {
			httpPath = "/conn-ids"
		}
		if !strings.HasPrefix(httpPath, "/") {
			httpPath = "/" + httpPath
		}
		mux := http.NewServeMux()
		mux.HandleFunc(httpPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			// v5: time-limited HMAC instead of the raw shared secret, so the
			// secret never crosses the (possibly plain-HTTP) link. The response
			// is signed too, so a man-in-the-middle can't feed the cloud
			// function a fake adapter connection ID. The IAM token is no
			// longer accepted here (it used to arrive in clear text).
			assign := r.URL.Query().Get("assign")
			want := r.URL.Query().Get("want")
			ts, ok := keys.VerifyConnIDsAuth(r.Header.Get("Authorization"), assign, want, time.Now())
			if !ok {
				log.Printf("[WARN] %s unauthorized request from %s", httpPath, r.RemoteAddr)
				// Plain 404: don't advertise that something lives here.
				http.NotFound(w, r)
				return
			}
			own := ups.OwnConnID()
			if own != "" && assign != "" && len(assign) <= 128 {
				// The function asks us to allocate (or look up) the shortId
				// for a newly authenticated helper connection.
				w8, _ := strconv.Atoi(want)
				if w8 < 0 || w8 > 255 {
					w8 = 0
				}
				if sid := ups.AssignHelper(assign, byte(w8)); sid != 0 {
					log.Printf("[INFO] assigned helper shortID=%d connId=%s", sid, assign)
				}
			}
			peer := ups.PeerConnID()
			helpers := ups.Helpers()
			if own == "" {
				log.Printf("[INFO] %s requested from %s but adapter not connected yet", httpPath, r.RemoteAddr)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			log.Printf("[INFO] %s requested from %s adapterConnId=%s helpers=%d", httpPath, r.RemoteAddr, own, len(helpers))
			// helpers field is the multi-helper map (preferred by the cloud
			// function on cold-start recovery). helperConnId is preserved for
			// compatibility with older cloud-function deployments that only
			// understand a single helper.
			helperList := make([]map[string]any, 0, len(helpers))
			for sid, cid := range helpers {
				helperList = append(helperList, map[string]any{
					"shortId": sid,
					"connId":  cid,
				})
			}
			resp := map[string]any{
				"adapterConnId": own,
				"helperConnId":  peer, // legacy single-helper compat
				"helpers":       helperList,
			}
			body, err := json.Marshal(resp)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-BTF-Sig", keys.ConnIDsRespSig(ts, body))
			w.Write(body)
		})
		addr := fmt.Sprintf(":%d", cfg.HTTP.ListenPort)
		// This endpoint is exposed to the public internet (the cloud function
		// polls it on cold start). Set timeouts so slow or half-open clients
		// can't tie up connections indefinitely (Slowloris-style exhaustion).
		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			log.Printf("[INFO] HTTP server starting addr=%s", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server: %v", err)
			}
		}()
		go func() { <-ctx.Done(); srv.Close() }()
	}

	log.Printf("[INFO] adapter starting target=%s coalesce=%v e2e=%v", cfg.Target.Address, cfg.CoalesceDelay(), keys.E2E)
	ups.Run(ctx)
}

func handleOpen(cfg *config.Config, sm *streams.Manager, streamID uint32) {
	conn, err := net.DialTimeout("tcp", cfg.Target.Address, 10*time.Second)
	if err != nil {
		log.Printf("[WARN] target connect failed stream=%d err=%v", streamID, err)
		sm.SendFrame(protocol.Frame{Type: protocol.MsgOpenFail, StreamID: streamID, Payload: []byte(err.Error())})
		sm.Remove(streamID) // drop the seq counter / reorder buffer for this stream
		return
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	s := &streams.Stream{ID: streamID, Conn: conn}
	sm.Register(s)

	if err := sm.SendFrame(protocol.Frame{Type: protocol.MsgOpenOK, StreamID: streamID}); err != nil {
		log.Printf("[WARN] send OPEN_OK failed stream=%d err=%v", streamID, err)
		conn.Close()
		sm.Remove(streamID)
		return
	}

	log.Printf("[INFO] stream opened stream=%d target=%s", streamID, cfg.Target.Address)
	sm.ReadLoop(s)
}

// handleProbe synthesises an HTTP/1.1 200 OK response without dialling any
// target. Triggered by an OPEN whose streamID has the PROBE bit set (see
// protocol.StreamProbeFlag). The probe round-trip exercises the full wsApi
// data path — helper → wsApi → adapter and adapter → wsApi → helper — so
// the helper can confirm bidirectional connectivity is actually working,
// independently of whether the adapter's configured target is reachable.
func handleProbe(sm *streams.Manager, streamID uint32) {
	log.Printf("[INFO] probe stream=%d: synthesising HTTP 200 OK (no target dial)", streamID)

	if err := sm.SendFrame(protocol.Frame{Type: protocol.MsgOpenOK, StreamID: streamID}); err != nil {
		log.Printf("[WARN] probe OPEN_OK send failed stream=%d: %v", streamID, err)
		return
	}

	body := "HTTP/1.1 200 OK\r\n" +
		"Server: bridge-to-freedom-adapter\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 2\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"OK"
	if err := sm.SendFrame(protocol.Frame{
		Type:     protocol.MsgData,
		StreamID: streamID,
		Payload:  []byte(body),
	}); err != nil {
		log.Printf("[WARN] probe DATA send failed stream=%d: %v", streamID, err)
		return
	}
	if err := sm.SendFrame(protocol.Frame{Type: protocol.MsgFin, StreamID: streamID}); err != nil {
		log.Printf("[WARN] probe FIN send failed stream=%d: %v", streamID, err)
		return
	}
	log.Printf("[INFO] probe stream=%d: response sent (%d bytes)", streamID, len(body))
}
