package keyring

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

type memoryBackend struct {
	mu    sync.Mutex
	items map[string][]byte
	err   error
	calls int
}

func (b *memoryBackend) Load(service, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return nil, b.err
	}
	value, ok := b.items[service+"/"+key]
	if !ok {
		return nil, ErrNotFound
	}
	return bytes.Clone(value), nil
}

func (b *memoryBackend) Save(service, key string, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return b.err
	}
	b.items[service+"/"+key] = bytes.Clone(value)
	return nil
}

func (b *memoryBackend) Delete(service, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return b.err
	}
	if _, ok := b.items[service+"/"+key]; !ok {
		return ErrNotFound
	}
	delete(b.items, service+"/"+key)
	return nil
}

func TestStoreIsolationAndLifecycle(t *testing.T) {
	backend := &memoryBackend{items: make(map[string][]byte)}
	production := NewWithBackend("isolated-production", backend)
	development := NewWithBackend("isolated-development", backend)
	secret := []byte("synthetic OAuth credential")
	if err := production.Save("authorization", secret); err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if _, err := development.Load("authorization"); !errors.Is(err, ErrNotFound) {
		t.Fatal("different services shared credentials")
	}
	loaded, err := production.Load("authorization")
	if err != nil || string(loaded) != "synthetic OAuth credential" {
		t.Fatal("saved credentials did not round-trip")
	}
	clear(loaded)
	loaded, err = production.Load("authorization")
	if err != nil || string(loaded) != "synthetic OAuth credential" {
		t.Fatal("mutating a read buffer changed the saved credential")
	}
	if err := production.Delete("authorization"); err != nil {
		t.Fatal(err)
	}
	if err := production.Delete("authorization"); err != nil {
		t.Fatal("deleting an already absent credential should be idempotent")
	}
	if _, err := production.Load("authorization"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted credentials were still available")
	}
}

func TestStoreValidatesBeforeNativeAccess(t *testing.T) {
	backend := &memoryBackend{items: make(map[string][]byte)}
	store := NewWithBackend("test", backend)
	for _, key := range []string{"", "bad\x00key", strings.Repeat("x", 129), string([]byte{0xff})} {
		if _, err := store.Load(key); err == nil {
			t.Fatal("invalid read identifier was accepted")
		}
		if err := store.Save(key, []byte("synthetic")); err == nil {
			t.Fatal("invalid write identifier was accepted")
		}
		if err := store.Delete(key); err == nil {
			t.Fatal("invalid delete identifier was accepted")
		}
	}
	for _, value := range [][]byte{nil, {}, make([]byte, MaxValueBytes+1)} {
		if err := store.Save("authorization", value); err == nil {
			t.Fatal("invalid credential size was accepted")
		}
	}
	if backend.calls != 0 {
		t.Fatal("invalid input reached the operating-system credential store")
	}
}

func TestStorePropagatesNativeFailure(t *testing.T) {
	failure := errors.New("synthetic credential store failure")
	backend := &memoryBackend{items: make(map[string][]byte), err: failure}
	store := NewWithBackend("test", backend)
	if _, err := store.Load("authorization"); !errors.Is(err, failure) {
		t.Fatal("load failure was hidden")
	}
	if err := store.Save("authorization", []byte("synthetic")); !errors.Is(err, failure) {
		t.Fatal("save failure was hidden")
	}
	if err := store.Delete("authorization"); !errors.Is(err, failure) {
		t.Fatal("delete failure was hidden")
	}
	if len(backend.items) != 0 {
		t.Fatal("failed write persisted a credential")
	}
	backend.err = nil
	backend.items["test/authorization"] = make([]byte, MaxValueBytes+1)
	if _, err := store.Load("authorization"); err == nil {
		t.Fatal("oversized saved credentials were accepted")
	}
}

func TestDenialStopsReadsWritesAndCleanupUntilExplicitRetry(t *testing.T) {
	for _, deniedOperation := range []string{"read", "save", "delete"} {
		t.Run(deniedOperation, func(t *testing.T) {
			backend := &memoryBackend{items: map[string][]byte{}, err: ErrAccessDenied}
			store := NewWithBackend("isolated-denial-test", backend)
			denials := 0
			store.OnAccessDenied = func() { denials++ }
			operations := map[string]func() error{
				"read":   func() error { _, err := store.Load("authorization"); return err },
				"save":   func() error { return store.Save("new-authorization", []byte("synthetic")) },
				"delete": func() error { return store.Delete("cleanup") },
			}
			if err := operations[deniedOperation](); !errors.Is(err, ErrAccessDenied) {
				t.Fatal("native refusal was not preserved")
			}
			backend.err = nil
			for range 10 {
				for _, operation := range operations {
					if err := operation(); !errors.Is(err, ErrAccessDenied) {
						t.Fatal("automatic access resumed after refusal")
					}
				}
			}
			if backend.calls != 1 || denials != 1 || len(backend.items) != 0 {
				t.Fatalf("denied access reached native store again: calls=%d notifications=%d", backend.calls, denials)
			}
			store.RetryAccess()
			if err := store.Save("authorization", []byte("synthetic")); err != nil || backend.calls != 2 {
				t.Fatal("explicit retry did not restore access")
			}
		})
	}
}

func TestConcurrentDeniedReadsOnlyPromptOnce(t *testing.T) {
	backend := &memoryBackend{items: map[string][]byte{}, err: ErrAccessDenied}
	store := NewWithBackend("isolated-concurrent-denial", backend)
	var requests sync.WaitGroup
	for range 20 {
		requests.Go(func() {
			if _, err := store.Load("authorization"); !errors.Is(err, ErrAccessDenied) {
				t.Error("concurrent request ignored the refusal")
			}
		})
	}
	requests.Wait()
	if backend.calls != 1 {
		t.Fatalf("concurrent requests opened %d native prompts", backend.calls)
	}
}

func TestUnusableClassifiesPermanentFailures(t *testing.T) {
	for _, err := range []error{ErrUnavailable, ErrAccessDenied, ErrStoreMissing} {
		if !Unusable(err) {
			t.Fatalf("%v was not classified as unusable", err)
		}
	}
	if Unusable(ErrNotFound) || Unusable(errors.New("transient")) {
		t.Fatal("a recoverable failure was classified as unusable")
	}
}
