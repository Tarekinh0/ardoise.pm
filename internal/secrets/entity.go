package secrets

import "fmt"

// EntityType identifies the kind of secret detected.
type EntityType string

const (
	JWT        EntityType = "JWT"
	Secret     EntityType = "SECRET"
	PrivateKey EntityType = "PRIVATE_KEY"
)

// SourceKind tags how the entity was detected (provenance).
type SourceKind string

const (
	SourceStructural SourceKind = "structural"
	SourcePrefix     SourceKind = "prefix"
	SourceEntropy    SourceKind = "entropy"
	SourcePEMArmor   SourceKind = "pem_armor"
)

// Entity represents a detected secret with position and metadata.
//
// CRITICAL: The Value field contains the actual secret. It must NEVER be
// logged, printed, or included in error messages. Use SafeString() for any
// output; the public API (Detecter) only ever exposes a redacted excerpt.
type Entity struct {
	Value      string     `json:"-"` // secret value — MUST NEVER BE LOGGED
	Type       EntityType `json:"type"`
	Source     SourceKind `json:"source"`
	Confidence float64    `json:"confidence"`
	Start      int        `json:"start"` // byte offset in original text
	End        int        `json:"end"`   // byte offset (exclusive)
}

// SafeString returns a redacted representation of the entity suitable for
// logging and debugging. It never includes the Value field.
//
// Format: "TYPE(src=source, conf=0.XX, pos=start-end)"
func (e Entity) SafeString() string {
	return fmt.Sprintf("%s(src=%s, conf=%.2f, pos=%d-%d)",
		e.Type, e.Source, e.Confidence, e.Start, e.End)
}

// String returns SafeString() — this ensures that even accidental use of
// fmt.Sprintf("%s", entity) or fmt.Println(entity) never leaks the secret.
func (e Entity) String() string {
	return e.SafeString()
}
