package domain

type Role string

const (
	Admin Role = "admin"
	User  Role = "user"
)

// Principal must be constructed from a verified server-side session, never
// request JSON or client identity headers. Zero values have no permissions.
type Principal struct {
	UserID        string
	Role          Role
	Authenticated bool
	Disabled      bool
}

func (p Principal) CanManage() bool {
	return p.Authenticated && !p.Disabled && p.UserID != "" && p.Role == Admin
}

// CanAccessApp requires the caller to supply a current, server-side grant for
// this exact user/app pair. This helper is not a permission cache or lookup.
func (p Principal) CanAccessApp(currentGrant bool) bool {
	if !p.Authenticated || p.Disabled || p.UserID == "" {
		return false
	}
	return p.Role == Admin || (p.Role == User && currentGrant)
}
