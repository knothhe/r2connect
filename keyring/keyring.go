// Package keyring keeps r2connect secrets in the operating-system credential
// store: the macOS Keychain, Windows Credential Manager or a freedesktop Secret
// Service keyring on Linux. *Store satisfies r2connect.SecretStore.
package keyring

import (
	"errors"
	"strings"
	"sync"
	"unicode/utf8"
)

var (
	ErrNotFound    = errors.New("credentials are not saved on this device")
	ErrUnavailable = errors.New("the operating-system credential store is unavailable on this platform")
	// ErrAccessDenied reports that the user refused or dismissed a credential
	// store prompt. A Store then stops all access until RetryAccess.
	ErrAccessDenied = errors.New("credential access was denied; automatic retries have stopped")
	ErrIncomplete   = errors.New("saved credentials are incomplete; save them again")
)

// MaxValueBytes bounds one saved value.
const MaxValueBytes = 64 << 10

// Backend performs single operations on a native credential store. service
// namespaces the keys; Delete of a missing key returns ErrNotFound.
type Backend interface {
	Load(service, key string) ([]byte, error)
	Save(service, key string, value []byte) error
	Delete(service, key string) error
}

// Store validates keys and values before they reach its Backend and remembers
// a refusal, so background work cannot keep reopening the store's prompt.
type Store struct {
	mu           sync.Mutex
	service      string
	backend      Backend
	accessDenied bool
	// OnAccessDenied, when set, runs once each time access becomes denied.
	OnAccessDenied func()
}

// New returns a Store for service on the platform's native credential store.
// label is the name the store's management UI shows for saved items.
func New(service, label string) *Store {
	return NewWithBackend(service, Native(label))
}

// NewWithBackend returns a Store on another Backend, such as one in memory for
// tests.
func NewWithBackend(service string, backend Backend) *Store {
	return &Store{service: service, backend: backend}
}

// Unusable reports that this device cannot keep secrets in its credential
// store, as opposed to a transient failure.
func Unusable(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrStoreMissing)
}

// ValidKey reports whether key can name a saved value.
func ValidKey(key string) bool {
	return key != "" && len(key) <= 128 && utf8.ValidString(key) && !strings.ContainsRune(key, '\x00')
}

// A native denial applies to the whole store, including cleanup writes and
// deletes. Serialize native calls so queued requests cannot reopen the prompt
// after the first request has already been denied.
func (s *Store) access(operation func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessDenied {
		return ErrAccessDenied
	}
	err := operation()
	if errors.Is(err, ErrAccessDenied) {
		s.accessDenied = true
		if s.OnAccessDenied != nil {
			s.OnAccessDenied()
		}
		return ErrAccessDenied
	}
	return err
}

// RetryAccess allows the store to prompt again after a refusal. Call it only
// for an explicit user action; polling, background work, cleanup and status
// reads must never call it.
func (s *Store) RetryAccess() {
	s.mu.Lock()
	s.accessDenied = false
	s.mu.Unlock()
}

func (s *Store) Load(key string) ([]byte, error) {
	if !ValidKey(key) {
		return nil, errors.New("invalid credential identifier")
	}
	var value []byte
	err := s.access(func() error {
		var err error
		value, err = s.backend.Load(s.service, key)
		return err
	})
	if err != nil {
		clear(value)
		return nil, err
	}
	if len(value) == 0 || len(value) > MaxValueBytes {
		clear(value)
		return nil, errors.New("invalid saved credentials")
	}
	return value, nil
}

func (s *Store) Save(key string, value []byte) error {
	if !ValidKey(key) {
		return errors.New("invalid credential identifier")
	}
	if len(value) == 0 || len(value) > MaxValueBytes {
		return errors.New("credentials must contain between 1 and 65536 bytes")
	}
	return s.access(func() error { return s.backend.Save(s.service, key, value) })
}

// Delete removes a saved value. Deleting a missing value succeeds.
func (s *Store) Delete(key string) error {
	if !ValidKey(key) {
		return errors.New("invalid credential identifier")
	}
	err := s.access(func() error { return s.backend.Delete(s.service, key) })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
