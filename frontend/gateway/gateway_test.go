package gateway

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
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

// TestConnCloseUnblocksReaderInPipeMode reproduces the production conn
// shape (Reader and Closer are different ends of different os.Pipe
// pairs, with the "other ends" held by a separate process via
// inherited fds) and asserts that *conn.Close unblocks an in-flight
// Read on the Reader side. Without an explicit Close on the Reader fd,
// closing only the Closer leaves the read parked because the
// duplicate fd (modeled here by a kept-alive pw2Dup) prevents the
// kernel from sending EOF on the read side. This is the goroutine-leak
// failure mode in readPrefaceWithTimeout's timeout path.
func TestConnCloseUnblocksReaderInPipeMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Pipe semantics around dup'd fds differ on windows; production runc-spawn path is linux-only")
	}

	pr1, pw1, err := os.Pipe()
	require.NoError(t, err)
	pr2, pw2, err := os.Pipe()
	require.NoError(t, err)

	// Simulate the runc-spawned frontend's inherited Stdout: a duplicate
	// fd of pw2 held by the "child". In production this is the runc
	// process's Stdout; here we hold a separate *os.File pointing at the
	// same pipe write end via dup(). While this fd is open, closing pw2
	// alone in the parent does not cause pr2 to see EOF.
	pw2Fd, err := dupFD(int(pw2.Fd()))
	require.NoError(t, err)
	pw2Dup := os.NewFile(uintptr(pw2Fd), "pw2-dup")
	defer pw2Dup.Close()

	c := &conn{
		Reader: pr2,
		Writer: pw1,
		Closer: pw2,
	}

	// Sanity: keep pr1 alive so the Writer side has a peer; otherwise
	// the parent's first write would EPIPE in unrelated test paths.
	_ = pr1

	// Start a Read that will block until either data arrives on pr2 or
	// pr2 is closed. In production this is the io.ReadFull goroutine
	// inside readPrefaceWithTimeout.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 24)
		_, err := io.ReadFull(c, buf)
		readDone <- err
	}()

	// Give the goroutine a moment to actually park on Read.
	time.Sleep(50 * time.Millisecond)

	// Close the conn. The fix asserts that this closes the Reader fd
	// (pr2) and unblocks io.ReadFull, even though the simulated child
	// process (pw2Dup) still holds a writer-side fd open.
	require.NoError(t, c.Close())

	select {
	case err := <-readDone:
		// io.ReadFull returns either io.ErrUnexpectedEOF or a closed-pipe
		// error depending on which side wins the close race; both are
		// acceptable for the leak-fix assertion (the goroutine exited).
		require.Error(t, err)
		require.True(t,
			errors.Is(err, io.ErrUnexpectedEOF) ||
				errors.Is(err, os.ErrClosed) ||
				errors.Is(err, io.EOF),
			"expected close-pipe-style error, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("io.ReadFull goroutine still blocked 2s after conn.Close; goroutine-leak fix regressed")
	}
}

// TestConnCloseIsIdempotent asserts that calling Close more than once
// (which happens in production: defer lbf.conn.Close, the ctx.Done
// goroutine in serve, and read-error paths can all fire) does not
// panic and is safe.
func TestConnCloseIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Pipe semantics differ on windows")
	}

	pr1, pw1, err := os.Pipe()
	require.NoError(t, err)
	pr2, pw2, err := os.Pipe()
	require.NoError(t, err)
	defer pr1.Close()

	c := &conn{
		Reader: pr2,
		Writer: pw1,
		Closer: pw2,
	}

	require.NoError(t, c.Close())
	// Second close should not panic. os.File.Close on an already-closed
	// file returns an error that callers (defer/ignore) can drop.
	_ = c.Close()
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
