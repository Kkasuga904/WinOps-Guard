package logging

import (
	"log"
	"os"
)

// Logger is a thin wrapper to standard log with fixed flags.
var Logger = log.New(os.Stdout, "winopsguard ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
