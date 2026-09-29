package wsapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	ws "github.com/yandex-cloud/go-genproto/yandex/cloud/serverless/apigateway/websocket/v1"
)

const grpcEndpoint = "apigateway-connections.api.cloud.yandex.net:443"

// callTimeout bounds each wsSend/Disconnect RPC. Without it a hung YC API call
// would block the calling stream's read loop indefinitely (no progress, no
// error, no teardown). The data path is normally sub-second; this is only a
// safety net so a stuck call eventually fails and the stream can recover.
const callTimeout = 20 * time.Second

type grpcClient struct {
	mu     sync.Mutex
	client ws.ConnectionServiceClient
	conn   *grpc.ClientConn
}

// ensure lazily builds the gRPC client. Unlike a sync.Once, a transient
// failure is NOT cached permanently: the next call retries, so the process can
// recover instead of being wedged for its whole lifetime by one early error.
func (g *grpcClient) ensure() (ws.ConnectionServiceClient, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.client != nil {
		return g.client, nil
	}
	endpoint := grpcEndpoint
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	// Test hook: BTF_TEST_WSAPI_ENDPOINT points the client at a local fake
	// API. It is only honoured for loopback addresses, so it can never be
	// used to send IAM tokens to a remote host in clear text.
	if ep := os.Getenv("BTF_TEST_WSAPI_ENDPOINT"); ep != "" {
		host, _, err := net.SplitHostPort(ep)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("BTF_TEST_WSAPI_ENDPOINT must be a loopback host:port")
		}
		endpoint = ep
		creds = insecure.NewCredentials()
		log.Println("[WARN] using TEST wsApi endpoint", ep)
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %w", err)
	}
	g.conn = conn
	g.client = ws.NewConnectionServiceClient(conn)
	log.Println("[INFO] gRPC WS API client initialized:", endpoint)
	return g.client, nil
}

func (g *grpcClient) authCtx(iamToken string) (context.Context, context.CancelFunc) {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + iamToken,
	})
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	return metadata.NewOutgoingContext(ctx, md), cancel
}

func (g *grpcClient) Send(connectionID string, data []byte, dataType string, iamToken string) error {
	client, err := g.ensure()
	if err != nil {
		return err
	}

	t := ws.SendToConnectionRequest_BINARY
	if dataType == "TEXT" {
		t = ws.SendToConnectionRequest_TEXT
	}

	ctx, cancel := g.authCtx(iamToken)
	defer cancel()
	_, err = client.Send(ctx, &ws.SendToConnectionRequest{
		ConnectionId: connectionID,
		Data:         data,
		Type:         t,
	})
	if err != nil {
		log.Printf("[WARN] wsapi.Send failed connId=%s bytes=%d err=%v", connectionID, len(data), err)
	}
	return err
}

func (g *grpcClient) Disconnect(connectionID string, iamToken string) error {
	client, err := g.ensure()
	if err != nil {
		return err
	}

	ctx, cancel := g.authCtx(iamToken)
	defer cancel()
	_, err = client.Disconnect(ctx, &ws.DisconnectRequest{
		ConnectionId: connectionID,
	})
	if err != nil {
		log.Printf("[WARN] wsapi.Disconnect failed connId=%s err=%v", connectionID, err)
	}
	return err
}
