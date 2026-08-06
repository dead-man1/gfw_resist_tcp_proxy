package tunnel

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/config"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/logx"
	"github.com/GFW-knocker/gfw_resist_tcp_proxy/internal/transport"
)

// lockedBuf collects log output written from the server's goroutines.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestServerLogRedactsClientIP drives a real client hello into a real server and
// inspects what the server actually logged at each level. The client is on
// loopback, so its address is 127.0.0.1:<port> and masking must reduce it to
// 127.0.*.*:<port>.
func TestServerLogRedactsClientIP(t *testing.T) {
	cases := []struct {
		level    string
		wantLine bool   // does "new client connected" appear at all?
		wantPeer string // substring the peer attr must contain ("" = no peer attr)
	}{
		{level: "debug", wantLine: true, wantPeer: "peer=127.0.0.1:"},
		{level: "info", wantLine: true, wantPeer: "peer=127.0.*.*:"},
		{level: "none", wantLine: false},
	}

	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			level, err := logx.ParseLevel(tc.level)
			if err != nil {
				t.Fatal(err)
			}
			logx.SetLevel(level)
			defer logx.SetLevel(slog.LevelInfo)

			out := &lockedBuf{}
			logger := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: level}))

			params := testParams(config.TransportKCP)
			serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			clientPC, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			lis, err := transport.Listen(serverPC, params)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() {
				cancel()
				lis.Close()
				serverPC.Close()
				clientPC.Close()
			})

			srv := NewServer(config.ServerConfig{BackendIP: "127.0.0.1"}, params.Key, logger)
			go srv.Serve(ctx, lis)

			sess, err := transport.Dial(ctx, clientPC, serverPC.LocalAddr(), params)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer sess.Close()
			if err := Verify(sess, params.Key); err != nil { // triggers the hello the server logs
				t.Fatalf("verify: %v", err)
			}

			// The server logs from its own goroutine; give it a moment to land. When
			// we expect silence there is nothing to wait for, so a short grace
			// period is enough to catch a line that should not be there.
			deadline := time.Now().Add(3 * time.Second)
			if !tc.wantLine {
				deadline = time.Now().Add(300 * time.Millisecond)
			}
			for time.Now().Before(deadline) {
				if tc.wantLine && strings.Contains(out.String(), "new client connected") {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			got := out.String()

			if tc.wantLine && !strings.Contains(got, "new client connected") {
				t.Fatalf("expected the connect line at level %s, log was:\n%s", tc.level, got)
			}
			if !tc.wantLine {
				if got != "" {
					t.Fatalf("level %s must log nothing, got:\n%s", tc.level, got)
				}
				return
			}
			if !strings.Contains(got, tc.wantPeer) {
				t.Errorf("level %s: log should contain %q, got:\n%s", tc.level, tc.wantPeer, got)
			}
			if tc.level != "debug" && strings.Contains(got, "127.0.0.1:") {
				t.Errorf("level %s leaked a full client address:\n%s", tc.level, got)
			}
		})
	}
}
