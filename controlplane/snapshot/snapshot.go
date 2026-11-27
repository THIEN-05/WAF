// Package snapshot exposes the snapshot build contracts used by the worker and
// cross-package edge contract tests. Database adapters remain in internal/snapshot.
package snapshot

import internal "github.com/example/wafplatform/controlplane/internal/snapshot"

type Candidate = internal.Candidate
type Record = internal.Record
type Repository = internal.Repository
type Objects = internal.Objects
type Signer = internal.Signer
type SecretSigner = internal.SecretSigner
type Builder = internal.Builder
type Warning = internal.Warning
type EdgeHandler = internal.EdgeHandler
type UpdateNotifier = internal.UpdateNotifier

var ErrNoSnapshot = internal.ErrNoSnapshot
var NotifyUpdated = internal.NotifyUpdated
var RunDebounced = internal.RunDebounced
