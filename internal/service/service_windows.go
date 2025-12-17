//go:build windows

package service

import (
	"errors"
)

// Run would integrate with Windows Service Control Manager.
// For MVP sample, service management is not activated.
func Run() error {
	return errors.New("windows service integration not implemented in MVP stub; run binary directly")
}
