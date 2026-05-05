package gateway

import (
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

func TestReadPrefaceWithTimeoutSuccess(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

	go func() {
		_, _ = c2.Write(preface)
	}()

	require.NoError(t, readPrefaceWithTimeout(c1, 5*time.Second))
}

func TestReadPrefaceWithTimeoutFiresOnSlowSender(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	// Sender writes nothing; the timer race must fire and close c1.
	start := time.Now()
	err := readPrefaceWithTimeout(c1, 50*time.Millisecond)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, errPrefaceReadTimeout)
	require.GreaterOrEqual(t, elapsed, 40*time.Millisecond)
	require.Less(t, elapsed, 2*time.Second)

	// c1 should be closed by readPrefaceWithTimeout on the timeout path
	// to unblock the inner io.ReadFull goroutine.
	_, werr := c1.Write([]byte("x"))
	require.Error(t, werr)
}

func TestReadPrefaceWithTimeoutMismatch(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Sender writes 24 bytes that do NOT match the HTTP/2 client preface.
	bogus := []byte("NOT-A-VALID-PREFACE-XXXX")
	require.Equal(t, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), len(bogus))
	go func() {
		_, _ = c2.Write(bogus)
	}()

	require.ErrorIs(t, readPrefaceWithTimeout(c1, 5*time.Second), errPrefaceMismatch)
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
