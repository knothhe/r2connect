package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Windows Credential Manager caps one credential blob below the largest values
// a Store accepts. Longer values are split into items under a fresh generation
// and the primary item holds a manifest naming it, so an interrupted save leaves
// the previous value readable. Values never start with the magic, which keeps
// its original name so credentials saved by earlier racomi releases still load.
const (
	secretChunkMagic    = "\x00racomi-chunks-1:"
	maxSecretChunkCount = 64
)

// secretItems performs single-item operations on a native store.
type secretItems interface {
	load(target string) ([]byte, error)
	save(target string, value []byte) error
	delete(target string) error
}

type chunkedSecretBackend struct {
	items secretItems
	limit int
}

type secretChunks struct {
	generation string
	count      int
}

func secretChunkTarget(primary string, chunks secretChunks, index int) string {
	return primary + "#" + chunks.generation + "." + strconv.Itoa(index)
}

func parseSecretChunks(value []byte) (secretChunks, bool) {
	manifest, ok := strings.CutPrefix(string(value), secretChunkMagic)
	if !ok {
		return secretChunks{}, false
	}
	generation, count, ok := strings.Cut(manifest, ":")
	n, err := strconv.Atoi(count)
	if !ok || err != nil || generation == "" || n < 1 || n > maxSecretChunkCount {
		return secretChunks{}, false
	}
	return secretChunks{generation, n}, true
}

// current reports the chunks the primary item refers to, if any.
func (b chunkedSecretBackend) current(primary string) (secretChunks, bool) {
	value, err := b.items.load(primary)
	if err != nil {
		return secretChunks{}, false
	}
	defer clear(value)
	return parseSecretChunks(value)
}

// drop is best effort: unreferenced chunks are never read again.
func (b chunkedSecretBackend) drop(primary string, chunks secretChunks, count int) {
	for index := range count {
		_ = b.items.delete(secretChunkTarget(primary, chunks, index))
	}
}

func (b chunkedSecretBackend) Load(service, key string) ([]byte, error) {
	primary := service + "/" + key
	value, err := b.items.load(primary)
	if err != nil {
		return nil, err
	}
	chunks, ok := parseSecretChunks(value)
	if !ok {
		return value, nil
	}
	clear(value)
	var joined []byte
	for index := range chunks.count {
		part, err := b.items.load(secretChunkTarget(primary, chunks, index))
		if err != nil {
			clear(joined)
			if errors.Is(err, ErrNotFound) {
				err = ErrIncomplete
			}
			return nil, err
		}
		joined = append(joined, part...)
		clear(part)
	}
	return joined, nil
}

func (b chunkedSecretBackend) Save(service, key string, value []byte) error {
	if bytes.HasPrefix(value, []byte(secretChunkMagic)) {
		return errors.New("invalid credential value")
	}
	primary := service + "/" + key
	previous, hadChunks := b.current(primary)
	if len(value) <= b.limit {
		if err := b.items.save(primary, value); err != nil {
			return err
		}
	} else {
		random := make([]byte, 8)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		chunks := secretChunks{hex.EncodeToString(random), (len(value) + b.limit - 1) / b.limit}
		if chunks.count > maxSecretChunkCount {
			return errors.New("credentials are too large for the system credential store")
		}
		for index := range chunks.count {
			part := value[index*b.limit : min(len(value), (index+1)*b.limit)]
			if err := b.items.save(secretChunkTarget(primary, chunks, index), part); err != nil {
				b.drop(primary, chunks, index)
				return err
			}
		}
		manifest := secretChunkMagic + chunks.generation + ":" + strconv.Itoa(chunks.count)
		if err := b.items.save(primary, []byte(manifest)); err != nil {
			b.drop(primary, chunks, chunks.count)
			return err
		}
	}
	if hadChunks {
		b.drop(primary, previous, previous.count)
	}
	return nil
}

func (b chunkedSecretBackend) Delete(service, key string) error {
	primary := service + "/" + key
	previous, hadChunks := b.current(primary)
	if err := b.items.delete(primary); err != nil {
		return err
	}
	if hadChunks {
		b.drop(primary, previous, previous.count)
	}
	return nil
}
