//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyReload(c chan<- os.Signal) { signal.Notify(c, syscall.SIGHUP) }
