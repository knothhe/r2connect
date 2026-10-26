package keyring

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type memorySecretItems struct {
	items    map[string][]byte
	limit    int
	failSave string
}

func (m *memorySecretItems) load(target string) ([]byte, error) {
	value, ok := m.items[target]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (m *memorySecretItems) save(target string, value []byte) error {
	if len(value) == 0 || len(value) > m.limit {
		return errors.New("native item limit exceeded")
	}
	if m.failSave != "" && strings.Contains(target, m.failSave) {
		return errors.New("native save failed")
	}
	m.items[target] = bytes.Clone(value)
	return nil
}

func (m *memorySecretItems) delete(target string) error {
	if _, ok := m.items[target]; !ok {
		return ErrNotFound
	}
	delete(m.items, target)
	return nil
}

func TestChunkedSecretsRoundTripAndReplaceChunks(t *testing.T) {
	items := &memorySecretItems{items: map[string][]byte{}, limit: 64}
	backend := chunkedSecretBackend{items: items, limit: items.limit}
	long := []byte(`{"passphrase":"` + strings.Repeat("x", 200) + `"}`)
	if err := backend.Save("service", "key", long); err != nil {
		t.Fatal(err)
	}
	if got, err := backend.Load("service", "key"); err != nil || !bytes.Equal(got, long) {
		t.Fatalf("load=%q err=%v", got, err)
	}
	if len(items.items) != 1+(len(long)+63)/64 {
		t.Fatalf("items=%d for a %d-byte value", len(items.items), len(long))
	}
	// A shorter value replaces the manifest and leaves no orphaned chunks.
	short := []byte(`{"a":"b"}`)
	if err := backend.Save("service", "key", short); err != nil {
		t.Fatal(err)
	}
	if got, err := backend.Load("service", "key"); err != nil || !bytes.Equal(got, short) || len(items.items) != 1 {
		t.Fatalf("load=%q err=%v items=%d", got, err, len(items.items))
	}
	if err := backend.Save("service", "key", long); err != nil {
		t.Fatal(err)
	}
	if err := backend.Delete("service", "key"); err != nil || len(items.items) != 0 {
		t.Fatalf("delete err=%v left %d items", err, len(items.items))
	}
	if _, err := backend.Load("service", "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted value: %v", err)
	}
}

func TestChunkedSecretsInterruptedSaveKeepsPreviousValue(t *testing.T) {
	items := &memorySecretItems{items: map[string][]byte{}, limit: 64}
	backend := chunkedSecretBackend{items: items, limit: items.limit}
	previous := []byte(`{"passphrase":"` + strings.Repeat("p", 200) + `"}`)
	if err := backend.Save("service", "key", previous); err != nil {
		t.Fatal(err)
	}
	before := len(items.items)
	items.failSave = ".2"
	if err := backend.Save("service", "key", []byte(`{"passphrase":"`+strings.Repeat("n", 200)+`"}`)); err == nil {
		t.Fatal("save succeeded although a chunk failed")
	}
	items.failSave = ""
	if got, err := backend.Load("service", "key"); err != nil || !bytes.Equal(got, previous) {
		t.Fatalf("previous value after failed save: %q %v", got, err)
	}
	if len(items.items) != before {
		t.Fatalf("failed save left %d items, want %d", len(items.items), before)
	}
}

func TestChunkedSecretsReportMissingChunks(t *testing.T) {
	items := &memorySecretItems{items: map[string][]byte{}, limit: 64}
	backend := chunkedSecretBackend{items: items, limit: items.limit}
	if err := backend.Save("service", "key", []byte(strings.Repeat("v", 200))); err != nil {
		t.Fatal(err)
	}
	for target := range items.items {
		if strings.HasSuffix(target, ".1") {
			delete(items.items, target)
		}
	}
	if _, err := backend.Load("service", "key"); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("missing chunk: %v", err)
	}
	if err := backend.Save("service", "key", []byte(secretChunkMagic+"forged:1")); err == nil {
		t.Fatal("a value that looks like a manifest was stored")
	}
}
