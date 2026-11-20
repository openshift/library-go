package engine

// Role states who a process is with respect to the TLS artifacts of a
// rotation: the writer owns the full lifecycle, the healer restores only
// unusable artifacts. The zero value is invalid.
type Role int

const (
	// RoleWriter owns the full artifact lifecycle: creation, scheduled
	// rotation and metadata repair.
	RoleWriter Role = iota + 1

	// RoleHealer restores artifacts that are unusable: missing, expired, or
	// invalid. It never performs scheduled rotation and never repairs
	// metadata, so it cannot fight the writer.
	RoleHealer
)

// String renders the role for logs and error messages.
func (r Role) String() string {
	switch r {
	case RoleWriter:
		return "writer"
	case RoleHealer:
		return "healer"
	default:
		return "invalid"
	}
}
