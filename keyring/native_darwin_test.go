//go:build darwin && cgo

package keyring

import (
	"errors"
	"testing"
)

// These are Security.framework OSStatus values. No test calls the real Keychain.
func TestMacOSKeychainRefusalClassification(t *testing.T) {
	for _, status := range []int{-128, -25293, -25308} {
		var err error
		switch status {
		case -128:
			err = keychainError("read", -128)
		case -25293:
			err = keychainError("save", -25293)
		case -25308:
			err = keychainError("delete", -25308)
		}
		if !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("macOS status %d did not stop automatic credential access", status)
		}
	}
	if !errors.Is(keychainError("read", -25300), ErrNotFound) {
		t.Fatal("a missing credential was classified as refusal")
	}
	if errors.Is(keychainError("read", -25291), ErrAccessDenied) {
		t.Fatal("an unavailable Keychain was classified as user refusal")
	}
}
