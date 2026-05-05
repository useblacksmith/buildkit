package gateway

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckSourceIsAllowed(t *testing.T) {
	makeGatewayFrontend := func(sources []string) (*gatewayFrontend, error) {
		gw, err := NewGatewayFrontend(nil, sources)
		if err != nil {
			return nil, err
		}
		gw1 := gw.(*gatewayFrontend)
		return gw1, nil
	}

	var gw *gatewayFrontend
	var err error

	// no restrictions
	gw, err = makeGatewayFrontend([]string{})
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("anything")
	require.NoError(t, err)

	gw, err = makeGatewayFrontend([]string{"docker-registry.wikimedia.org/repos/releng/blubber/buildkit:9.9.9"})
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("docker-registry.wikimedia.org/repos/releng/blubber/buildkit")
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("docker-registry.wikimedia.org/repos/releng/blubber/buildkit:v1.2.3")
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("docker-registry.wikimedia.org/something-else")
	require.Error(t, err)

	gw, err = makeGatewayFrontend([]string{"alpine"})
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("alpine")
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("library/alpine")
	require.NoError(t, err)
	err = gw.checkSourceIsAllowed("docker.io/library/alpine")
	require.NoError(t, err)
}

func TestPrefaceConnReplaysBufferedBytes(t *testing.T) {
	// Pair of in-memory net.Conns; we'll wrap one end and verify that
	// reads on the wrapper first drain a pre-buffered chunk before
	// falling through to the underlying conn.
	c1, c2 := net.Pipe()
	defer c2.Close()

	const buffered = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	const trailing = "DATA-AFTER-PREFACE"
	pc := &prefaceConn{Conn: c1, buf: []byte(buffered)}

	// Writer goroutine pushes the trailing payload to the underlying conn,
	// then closes c2 so io.ReadAll terminates after draining the wrapper's
	// buffer and the trailing bytes from c1.
	go func() {
		_, _ = c2.Write([]byte(trailing))
		_ = c2.Close()
	}()

	out, err := io.ReadAll(pc)
	require.NoError(t, err)
	require.Equal(t, buffered+trailing, string(out))
}

func TestReadPrefaceWithTimeoutSuccess(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	go func() {
		_, _ = c2.Write(preface)
	}()

	got, err := readPrefaceWithTimeout(c1, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, preface, got)
}

func TestReadPrefaceWithTimeoutFiresOnSlowSender(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	// Sender writes nothing; the timer race must fire and close c1.
	start := time.Now()
	_, err := readPrefaceWithTimeout(c1, 50*time.Millisecond)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, errPrefaceReadTimeout)
	require.GreaterOrEqual(t, elapsed, 40*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second)

	// c1 should be closed by readPrefaceWithTimeout on the timeout path
	// to unblock the inner io.ReadFull goroutine.
	_, werr := c1.Write([]byte("x"))
	require.Error(t, werr)
}

func TestPrefaceReadTimeoutEnvOverride(t *testing.T) {
	t.Setenv(prefaceTimeoutEnvVar, "")
	require.Equal(t, defaultPrefaceTimeout, prefaceReadTimeout())

	t.Setenv(prefaceTimeoutEnvVar, "2m")
	require.Equal(t, 2*time.Minute, prefaceReadTimeout())

	// invalid value falls back to default
	t.Setenv(prefaceTimeoutEnvVar, "not-a-duration")
	require.Equal(t, defaultPrefaceTimeout, prefaceReadTimeout())

	// non-positive falls back to default
	t.Setenv(prefaceTimeoutEnvVar, "0s")
	require.Equal(t, defaultPrefaceTimeout, prefaceReadTimeout())
}
