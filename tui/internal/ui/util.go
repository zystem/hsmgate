package ui

import (
	"context"

	"github.com/zystem/hsmgate/tui/internal/sys"
)

func contextBackground() context.Context { return context.Background() }

// serviceUser is the account the service runs as, whose files these are: the one a package made, when there is one.
func (a *App) serviceUser() string {
	if sys.UserExists("hsmgate") {
		return "hsmgate"
	}
	return ""
}
