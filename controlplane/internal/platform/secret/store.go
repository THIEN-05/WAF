package secret

import (
	"context"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("secret not found")

// Store is the boundary to a production KMS/Secrets Manager. Implementations must not log values.
type Store interface {
	Get(context.Context, string) ([]byte, error)
	Put(context.Context, string, []byte) error
	Delete(context.Context, string) error
}

type Memory struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func NewMemory() *Memory { return &Memory{values: map[string][]byte{}} }
func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (m *Memory) Put(_ context.Context, key string, v []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = append([]byte(nil), v...)
	return nil
}
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
	return nil
}
