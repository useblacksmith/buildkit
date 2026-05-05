//go:build !windows

package gateway

import "syscall"

// dupFD returns a duplicate of the given file descriptor. Used only by
// tests in this package to simulate the runc-spawned child process
// holding an inherited fd of one end of an os.Pipe pair, so that
// closing the parent's end does not cause the other end to see EOF.
func dupFD(fd int) (int, error) {
	return syscall.Dup(fd)
}
