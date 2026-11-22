package main

import "os"

// The server is meant for Linux; on Windows it simply has no reload signal.
func notifyReload(chan<- os.Signal) {}
