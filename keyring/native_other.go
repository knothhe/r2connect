//go:build (!darwin && !windows && !linux) || (darwin && !cgo)

package keyring

// ErrStoreMissing reports that this account has no usable credential store.
var ErrStoreMissing = ErrUnavailable

type nativeBackend struct{}

// Native returns a backend that reports ErrUnavailable on this platform.
func Native(string) Backend { return nativeBackend{} }

func (nativeBackend) Load(string, string) ([]byte, error) {
	return nil, ErrUnavailable
}

func (nativeBackend) Save(string, string, []byte) error { return ErrUnavailable }
func (nativeBackend) Delete(string, string) error       { return ErrUnavailable }
