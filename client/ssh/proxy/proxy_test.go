package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/testutil"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "ssh" {
		if os.Args[2] == "exec" {
			if len(os.Args) > 3 {
				cmd := os.Args[3]
				if cmd == "echo" && len(os.Args) > 4 {
					fmt.Fprintln(os.Stdout, os.Args[4])
					os.Exit(0)
				}
			}
			fmt.Fprintf(os.Stderr, "Test binary called as 'ssh exec' with args: %v - preventing infinite recursion\n", os.Args)
			os.Exit(1)
		}
	}

	code := m.Run()

	testutil.CleanupTestUsers()

	os.Exit(code)
}

func TestSSHProxy_verifyHostKey(t *testing.T) {
	t.Run("calls daemon to verify host key", func(t *testing.T) {
		mockDaemon := startMockDaemon(t)
		defer mockDaemon.stop()

		grpcConn, err := grpc.NewClient(mockDaemon.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer func() { _ = grpcConn.Close() }()

		proxy := &SSHProxy{
			daemonAddr:   mockDaemon.addr,
			daemonClient: proto.NewDaemonServiceClient(grpcConn),
		}

		testKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		testPubKey, err := nbssh.GeneratePublicKey(testKey)
		require.NoError(t, err)

		mockDaemon.setHostKey("test-host", testPubKey)

		err = proxy.verifyHostKey("test-host", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, mustParsePublicKey(t, testPubKey))
		assert.NoError(t, err)
	})

	t.Run("rejects unknown host key", func(t *testing.T) {
		mockDaemon := startMockDaemon(t)
		defer mockDaemon.stop()

		grpcConn, err := grpc.NewClient(mockDaemon.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer func() { _ = grpcConn.Close() }()

		proxy := &SSHProxy{
			daemonAddr:   mockDaemon.addr,
			daemonClient: proto.NewDaemonServiceClient(grpcConn),
		}

		unknownKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
		require.NoError(t, err)
		unknownPubKey, err := nbssh.GeneratePublicKey(unknownKey)
		require.NoError(t, err)

		err = proxy.verifyHostKey("unknown-host", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, mustParsePublicKey(t, unknownPubKey))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer unknown-host not found in network")
	})
}

func TestSSHProxy_ForwardsInitialPTYSize(t *testing.T) {
	want := ssh.Window{Width: 120, Height: 34}
	initialWindow := make(chan ssh.Window, 1)
	backend := dialPTYTestServer(t, &ssh.Server{
		Handler: func(ssh.Session) {},
		PtyCallback: func(_ ssh.Context, pty ssh.Pty) bool {
			initialWindow <- pty.Window
			// Reject the PTY after capture so the test server never queues resize events.
			return false
		},
	})

	proxy := &SSHProxy{backendClient: backend, stderr: io.Discard}
	frontend := dialPTYTestServer(t, &ssh.Server{Handler: proxy.handleSSHSession})
	session, err := frontend.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	require.NoError(t, session.RequestPty("xterm", want.Height, want.Width, nil))
	require.NoError(t, session.Run("check-pty"))
	select {
	case got := <-initialWindow:
		assert.Equal(t, want, got, "backend should receive the requested initial PTY size")
	default:
		t.Fatal("backend did not receive an initial PTY request")
	}
}

func dialPTYTestServer(t *testing.T, server *ssh.Server) *cryptossh.Client {
	t.Helper()

	signer, err := generateHostKey()
	require.NoError(t, err)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server.HostSigners = []ssh.Signer{signer}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().String()
	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, &cryptossh.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptossh.FixedHostKey(signer.PublicKey()),
	})
	require.NoError(t, err)
	client := cryptossh.NewClient(clientConn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type mockDaemonServer struct {
	proto.UnimplementedDaemonServiceServer
	hostKeys map[string][]byte
	jwtToken string
}

func (m *mockDaemonServer) GetPeerSSHHostKey(ctx context.Context, req *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	key, found := m.hostKeys[req.PeerAddress]
	return &proto.GetPeerSSHHostKeyResponse{
		Found:      found,
		SshHostKey: key,
	}, nil
}

func (m *mockDaemonServer) RequestJWTAuth(ctx context.Context, req *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	return &proto.RequestJWTAuthResponse{
		CachedToken: m.jwtToken,
	}, nil
}

func (m *mockDaemonServer) WaitJWTToken(ctx context.Context, req *proto.WaitJWTTokenRequest) (*proto.WaitJWTTokenResponse, error) {
	return &proto.WaitJWTTokenResponse{
		Token: m.jwtToken,
	}, nil
}

type mockDaemon struct {
	addr   string
	server *grpc.Server
	impl   *mockDaemonServer
}

func startMockDaemon(t *testing.T) *mockDaemon {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	impl := &mockDaemonServer{
		hostKeys: make(map[string][]byte),
		jwtToken: "test-jwt-token",
	}

	grpcServer := grpc.NewServer()
	proto.RegisterDaemonServiceServer(grpcServer, impl)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return &mockDaemon{
		addr:   listener.Addr().String(),
		server: grpcServer,
		impl:   impl,
	}
}

func (m *mockDaemon) setHostKey(addr string, pubKey []byte) {
	m.impl.hostKeys[addr] = pubKey
}

func (m *mockDaemon) stop() {
	if m.server != nil {
		m.server.Stop()
	}
}

func mustParsePublicKey(t *testing.T, pubKeyBytes []byte) cryptossh.PublicKey {
	t.Helper()
	pubKey, _, _, _, err := cryptossh.ParseAuthorizedKey(pubKeyBytes)
	require.NoError(t, err)
	return pubKey
}
