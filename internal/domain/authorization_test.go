package domain

import "testing"

func TestDefaultDenyAuthorization(t *testing.T) {
	for _, role := range []Role{Admin, User, "", "superadmin"} {
		for _, authenticated := range []bool{false, true} {
			for _, disabled := range []bool{false, true} {
				for _, userID := range []string{"", "server-session-user"} {
					p := Principal{UserID: userID, Role: role, Authenticated: authenticated, Disabled: disabled}
					active := authenticated && !disabled && userID != ""
					if got := p.CanManage(); got != (active && role == Admin) {
						t.Errorf("management decision incorrect for %+v", p)
					}
					for _, grant := range []bool{false, true} {
						want := active && (role == Admin || role == User && grant)
						if got := p.CanAccessApp(grant); got != want {
							t.Errorf("app decision incorrect for %+v with grant=%v", p, grant)
						}
					}
				}
			}
		}
	}
}
