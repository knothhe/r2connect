//go:build windows

package keyring

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	winGenericCredential = 1
	winPersistLocal      = 2
	winMaxSecretBytes    = 5 * 512
)

// ERROR_NO_SUCH_LOGON_SESSION: the account has no credential store, as for
// some service and remote sessions.
const winNoLogonSession = windows.Errno(1312)

// ErrStoreMissing reports that this account has no usable credential store.
var ErrStoreMissing = errors.New("Windows Credential Manager is not available for this account.")

// Native returns the Credential Manager backend. Items record label as their
// user name; longer values are split across several items.
func Native(label string) Backend {
	return chunkedSecretBackend{items: winCredItems{label: label}, limit: winMaxSecretBytes}
}

// winCredItems stores single blobs.
type winCredItems struct{ label string }

// Layout follows CREDENTIALW from wincred.h. Secrets are passed to the native
// API in memory; they never enter a process command line or the clipboard.
type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         unsafe.Pointer
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	winCredLibrary = windows.NewLazySystemDLL("advapi32.dll")
	winCredRead    = winCredLibrary.NewProc("CredReadW")
	winCredWrite   = winCredLibrary.NewProc("CredWriteW")
	winCredDelete  = winCredLibrary.NewProc("CredDeleteW")
	winCredFree    = winCredLibrary.NewProc("CredFree")
)

func winCredentialError(operation string, err error) error {
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return ErrNotFound
	}
	if errors.Is(err, winNoLogonSession) {
		return ErrStoreMissing
	}
	code, ok := err.(syscall.Errno)
	if !ok || code == 0 {
		code = windows.ERROR_INVALID_FUNCTION
	}
	return fmt.Errorf("Windows Credential Manager could not %s credentials (code %d)", operation, uint32(code))
}

func (winCredItems) load(name string) ([]byte, error) {
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, errors.New("invalid credential identifier")
	}
	var credential *winCredential
	result, _, callErr := winCredRead.Call(uintptr(unsafe.Pointer(target)), winGenericCredential, 0, uintptr(unsafe.Pointer(&credential)))
	runtime.KeepAlive(target)
	if result == 0 {
		return nil, winCredentialError("read", callErr)
	}
	if credential == nil {
		return nil, errors.New("invalid saved credentials")
	}
	defer winCredFree.Call(uintptr(unsafe.Pointer(credential)))
	if credential.CredentialBlob == nil || credential.CredentialBlobSize == 0 || credential.CredentialBlobSize > winMaxSecretBytes {
		return nil, errors.New("invalid saved credentials")
	}
	return append([]byte(nil), unsafe.Slice(credential.CredentialBlob, int(credential.CredentialBlobSize))...), nil
}

func (w winCredItems) save(name string, value []byte) error {
	if len(value) == 0 || len(value) > winMaxSecretBytes {
		return errors.New("a credential item must contain between 1 and 2560 bytes")
	}
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return errors.New("invalid credential identifier")
	}
	username, err := windows.UTF16PtrFromString(w.label)
	if err != nil {
		return errors.New("invalid credential label")
	}
	credential := winCredential{Type: winGenericCredential, TargetName: target,
		CredentialBlobSize: uint32(len(value)), CredentialBlob: &value[0], Persist: winPersistLocal, UserName: username}
	result, _, callErr := winCredWrite.Call(uintptr(unsafe.Pointer(&credential)), 0)
	runtime.KeepAlive(value)
	runtime.KeepAlive(credential)
	if result == 0 {
		return winCredentialError("save", callErr)
	}
	return nil
}

func (winCredItems) delete(name string) error {
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return errors.New("invalid credential identifier")
	}
	result, _, callErr := winCredDelete.Call(uintptr(unsafe.Pointer(target)), winGenericCredential, 0)
	runtime.KeepAlive(target)
	if result == 0 {
		return winCredentialError("delete", callErr)
	}
	return nil
}
