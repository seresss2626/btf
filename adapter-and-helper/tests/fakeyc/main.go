// Command fakeyc is a TEST-ONLY stand-in for the Yandex Cloud WebSocket
// management gRPC API (ConnectionService.Send / Disconnect). It forwards
// every call to the local gateway simulator (tests/e2e/sim.js) over HTTP.
// Used by tests/e2e/run.sh; never deployed.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	ws "github.com/yandex-cloud/go-genproto/yandex/cloud/serverless/apigateway/websocket/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type srv struct {
	ws.UnimplementedConnectionServiceServer
	sim string
}

func (s *srv) call(ctx context.Context, path, conn string, body []byte) error {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := ""
	if v := md.Get("authorization"); len(v) > 0 {
		auth = v[0]
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", s.sim+path+"?conn="+url.QueryEscape(conn), bytes.NewReader(body))
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return nil
	case 404:
		return status.Error(codes.NotFound, "connection not found")
	case 401:
		return status.Error(codes.Unauthenticated, "bad iam token")
	default:
		return status.Error(codes.Internal, fmt.Sprint(resp.StatusCode))
	}
}

func (s *srv) Send(ctx context.Context, r *ws.SendToConnectionRequest) (*ws.SendToConnectionResponse, error) {
	return &ws.SendToConnectionResponse{}, s.call(ctx, "/send", r.ConnectionId, r.Data)
}

func (s *srv) Disconnect(ctx context.Context, r *ws.DisconnectRequest) (*ws.DisconnectResponse, error) {
	return &ws.DisconnectResponse{}, s.call(ctx, "/disconnect", r.ConnectionId, nil)
}

func main() {
	listen, sim := os.Args[1], os.Args[2]
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	ws.RegisterConnectionServiceServer(g, &srv{sim: sim})
	log.Printf("fakeyc gRPC on %s -> %s", listen, sim)
	log.Fatal(g.Serve(ln))
}
