//go:build windows

package gateway

import "errors"

// dupFD is a stub on windows; tests that call it gate themselves on
// runtime.GOOS != "windows" and do not exercise this path.
func dupFD(_ int) (int, error) {
	return 0, errors.New("dupFD not supported on windows")
}
