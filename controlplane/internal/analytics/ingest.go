package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/klauspost/compress/zstd"
)

const (
	BatchSchemaVersion = 1
	maxCompressedBatch = 4 << 20
	maxDecodedBatch    = 32 << 20
	maxBatchRows       = 10_000
)

type CompressedBatch struct {
	SchemaVersion int                   `json:"schema_version"`
	Events        []wafcore.LogEvent    `json:"events,omitempty"`
	SiteStats     []wafcore.SiteStats1m `json:"site_stats_1m,omitempty"`
}

type SiteIdentity struct {
	TenantID     string `json:"tenant_id"`
	RetentionDay uint16 `json:"retention_days"`
}

type SiteIdentityResolver interface {
	ResolveSite(context.Context, string) (SiteIdentity, error)
}

type EventRow struct {
	Event         wafcore.LogEvent
	RetentionDays uint16
}

type Rows struct {
	Events []EventRow
	Stats  []wafcore.SiteStats1m
}

type Processor struct{ Resolver SiteIdentityResolver }

func (p Processor) DecodeAndAuthorize(ctx context.Context, compressed []byte) (Rows, error) {
	if p.Resolver == nil {
		return Rows{}, errors.New("site identity resolver is required")
	}
	if len(compressed) == 0 || len(compressed) > maxCompressedBatch {
		return Rows{}, errors.New("compressed ingest batch exceeds size limit")
	}
	decoder, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderMaxMemory(maxDecodedBatch))
	if err != nil {
		return Rows{}, fmt.Errorf("decode ingest compression: %w", err)
	}
	defer decoder.Close()
	plain, err := io.ReadAll(io.LimitReader(decoder, maxDecodedBatch+1))
	if err != nil {
		return Rows{}, fmt.Errorf("read ingest batch: %w", err)
	}
	if len(plain) > maxDecodedBatch {
		return Rows{}, errors.New("decoded ingest batch exceeds size limit")
	}
	var batch CompressedBatch
	jsonDecoder := json.NewDecoder(bytes.NewReader(plain))
	jsonDecoder.DisallowUnknownFields()
	if err = jsonDecoder.Decode(&batch); err != nil {
		return Rows{}, fmt.Errorf("decode ingest schema: %w", err)
	}
	if batch.SchemaVersion != BatchSchemaVersion || len(batch.Events)+len(batch.SiteStats) > maxBatchRows {
		return Rows{}, errors.New("unsupported or oversized ingest batch")
	}
	var trailing any
	if err = jsonDecoder.Decode(&trailing); err != io.EOF {
		return Rows{}, errors.New("ingest payload contains trailing JSON")
	}
	rows := Rows{Events: make([]EventRow, 0, len(batch.Events)), Stats: make([]wafcore.SiteStats1m, 0, len(batch.SiteStats))}
	seenRequests := make(map[string]struct{}, len(batch.Events))
	for _, event := range batch.Events {
		if err = event.Validate(); err != nil {
			return Rows{}, fmt.Errorf("invalid event: %w", err)
		}
		identity, resolveErr := p.Resolver.ResolveSite(ctx, event.SiteID)
		if resolveErr != nil {
			return Rows{}, fmt.Errorf("resolve event site: %w", resolveErr)
		}
		if identity.TenantID == "" || identity.RetentionDay == 0 {
			return Rows{}, errors.New("site identity resolver returned incomplete policy")
		}
		event.TenantID = identity.TenantID // Tenant identity supplied by the edge is never authoritative.
		requestKey := event.SiteID + ":" + event.RequestID
		if _, duplicate := seenRequests[requestKey]; duplicate {
			continue
		}
		seenRequests[requestKey] = struct{}{}
		rows.Events = append(rows.Events, EventRow{Event: event, RetentionDays: identity.RetentionDay})
	}
	for _, stats := range batch.SiteStats {
		if err = stats.Validate(); err != nil {
			return Rows{}, fmt.Errorf("invalid site stats: %w", err)
		}
		identity, resolveErr := p.Resolver.ResolveSite(ctx, stats.SiteID)
		if resolveErr != nil {
			return Rows{}, fmt.Errorf("resolve stats site: %w", resolveErr)
		}
		if identity.TenantID == "" {
			return Rows{}, errors.New("site identity resolver returned empty tenant")
		}
		stats.TenantID = identity.TenantID
		rows.Stats = append(rows.Stats, stats)
	}
	return rows, nil
}
