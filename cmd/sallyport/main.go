package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/RHCloud1/sallyport/internal/client"
	"github.com/RHCloud1/sallyport/internal/door"
	"github.com/RHCloud1/sallyport/internal/server"
)

var version = "dev"

const usage = `usage:
  sallyport server -c server.json   run the site and tunnel endpoint
  sallyport client -c client.json   run the local SOCKS5/HTTP proxy
  sallyport genkey                  print a new user key
  sallyport version

The server reloads its config on SIGHUP (users, the proxy switch, logging,
certificate).`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(configFlag())
	case "client":
		runClient(configFlag())
	case "genkey":
		fmt.Println(door.NewKey())
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func configFlag() string {
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("c", "", "config file")
	fs.Parse(os.Args[2:])
	if *path == "" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	return *path
}

func runServer(path string) {
	s, err := server.New(path)
	if err != nil {
		log.Fatal(err)
	}
	hup := make(chan os.Signal, 1)
	notifyReload(hup)
	go func() {
		for range hup {
			if err := s.Reload(); err != nil {
				log.Printf("reload failed, keeping the old config: %v", err)
			}
		}
	}()
	log.Fatal(s.ListenAndServe())
}

func runClient(path string) {
	cfg, err := client.LoadConfig(path)
	if err != nil {
		log.Fatal(err)
	}
	c, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
