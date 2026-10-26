//go:build linux

package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

// Classification only; TestLinuxSecretServiceRoundTrip is the opt-in check
// against the user's real keyring.
func TestLinuxSecretServiceErrorClassification(t *testing.T) {
	for _, name := range []string{"org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner", "org.freedesktop.Secret.Error.NoSuchObject"} {
		if err := secretServiceError("read", dbus.Error{Name: name}); !errors.Is(err, errSecretServiceUnavailable) {
			t.Fatalf("%s was not reported as a missing keyring: %v", name, err)
		}
	}
	for _, err := range []error{dbus.Error{Name: "org.freedesktop.Secret.Error.IsLocked"}, dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", nil)} {
		if !errors.Is(secretServiceError("save", err), ErrAccessDenied) {
			t.Fatalf("%v did not stop automatic credential access", err)
		}
	}
	for _, err := range []error{ErrNotFound, ErrAccessDenied, errSecretServiceUnavailable} {
		if got := secretServiceError("delete", err); got != err {
			t.Fatalf("sentinel %v was rewritten as %v", err, got)
		}
	}
	other := secretServiceError("read", dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"})
	if errors.Is(other, ErrAccessDenied) || errors.Is(other, errSecretServiceUnavailable) {
		t.Fatalf("an unexpected keyring failure was misclassified: %v", other)
	}
}

func TestLinuxSecretServiceRoundTrip(t *testing.T) {
	if os.Getenv("R2CONNECT_TEST_SECRET_SERVICE") != "1" {
		t.Skip("set R2CONNECT_TEST_SECRET_SERVICE=1 to write a temporary item to the session keyring")
	}
	random := make([]byte, 8)
	_, _ = rand.Read(random)
	store := New("com.knothhe.r2connect.keyring.test-"+hex.EncodeToString(random), "r2connect test credentials")
	const key = "oauth-roundtrip"
	t.Cleanup(func() { _ = store.Delete(key) })
	if _, err := store.Load(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: %v", err)
	}
	for _, value := range [][]byte{[]byte("first\x00secret"), []byte("second")} {
		if err := store.Save(key, value); err != nil {
			t.Fatal(err)
		}
		got, err := store.Load(key)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("load=%q err=%v, want %q", got, err, value)
		}
	}
	if err := store.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted item still loads: %v", err)
	}
	if err := store.Delete(key); err != nil {
		t.Fatalf("deleting a missing item: %v", err)
	}
}
