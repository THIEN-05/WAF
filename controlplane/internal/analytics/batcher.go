package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrIngestQueueFull = errors.New("ingest queue is full")

type DeadLetterSink interface {
	Put(context.Context, []byte, error) error
}

type DeadLetterRecord struct {
	At      time.Time `json:"at"`
	Error   string    `json:"error"`
	Payload []byte    `json:"payload"`
}

type FileDeadLetter struct {
	Path string
	mu   sync.Mutex
}

func (d *FileDeadLetter) Put(_ context.Context, payload []byte, cause error) error {
	if d == nil || d.Path == "" || cause == nil {
		return errors.New("dead-letter path and cause are required")
	}
	encoded, err := json.Marshal(DeadLetterRecord{At: time.Now().UTC(), Error: cause.Error(), Payload: append([]byte(nil), payload...)})
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err = os.MkdirAll(filepath.Dir(d.Path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(d.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(encoded, '\n')); err != nil {
		return errors.Join(err, file.Close())
	}
	if err = file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

type queuedPayload struct{ raw []byte }

type Batcher struct {
	Processor     Processor
	Writer        BatchWriter
	DeadLetters   DeadLetterSink
	QueueSize     int
	MaxRows       int
	FlushInterval time.Duration
	queue         chan queuedPayload
}

func (b *Batcher) Enqueue(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxCompressedBatch {
		return errors.New("invalid ingest payload size")
	}
	if b.queue == nil {
		return errors.New("ingest batcher is not running")
	}
	copyOfPayload := append([]byte(nil), payload...)
	select {
	case b.queue <- queuedPayload{raw: copyOfPayload}:
		return nil
	default:
		return ErrIngestQueueFull
	}
}

func (b *Batcher) Run(ctx context.Context) error {
	if err := b.prepare(); err != nil {
		return err
	}
	return b.run(ctx)
}

func (b *Batcher) Start(ctx context.Context) (<-chan error, error) {
	if err := b.prepare(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- b.run(ctx) }()
	return done, nil
}

func (b *Batcher) prepare() error {
	if b.Processor.Resolver == nil || b.Writer == nil || b.DeadLetters == nil {
		return errors.New("ingest processor, writer, and dead-letter sink are required")
	}
	if b.QueueSize <= 0 {
		b.QueueSize = 4096
	}
	if b.MaxRows <= 0 || b.MaxRows > maxBatchRows {
		b.MaxRows = maxBatchRows
	}
	if b.FlushInterval <= 0 {
		b.FlushInterval = time.Second
	}
	if b.queue == nil {
		b.queue = make(chan queuedPayload, b.QueueSize)
	}
	return nil
}

func (b *Batcher) run(ctx context.Context) error {
	ticker := time.NewTicker(b.FlushInterval)
	defer ticker.Stop()
	rows := Rows{}
	rowCount := 0
	flush := func(flushCtx context.Context) error {
		if rowCount == 0 {
			return nil
		}
		writeErr := b.Writer.Write(flushCtx, rows)
		if writeErr != nil {
			deadRows := rows
			var partial *PartialWriteError
			if errors.As(writeErr, &partial) {
				deadRows = partial.Failed
			}
			failed, _ := json.Marshal(deadRows)
			if err := b.DeadLetters.Put(flushCtx, failed, writeErr); err != nil {
				return fmt.Errorf("write ClickHouse batch failed and dead-letter failed: %w", errors.Join(writeErr, err))
			}
		}
		rows = Rows{}
		rowCount = 0
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := flush(flushCtx); err != nil {
				return err
			}
			return nil
		case <-ticker.C:
			if err := flush(ctx); err != nil {
				return err
			}
		case item := <-b.queue:
			decoded, err := b.Processor.DecodeAndAuthorize(ctx, item.raw)
			if err != nil {
				if dlErr := b.DeadLetters.Put(ctx, item.raw, err); dlErr != nil {
					return fmt.Errorf("reject ingest payload and dead-letter failed: %w", errors.Join(err, dlErr))
				}
				continue
			}
			rows.Events = append(rows.Events, decoded.Events...)
			rows.Stats = append(rows.Stats, decoded.Stats...)
			rowCount += len(decoded.Events) + len(decoded.Stats)
			if rowCount >= b.MaxRows {
				if err := flush(ctx); err != nil {
					return err
				}
			}
		}
	}
}
