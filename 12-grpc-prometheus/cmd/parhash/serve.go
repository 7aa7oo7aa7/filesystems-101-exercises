package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"fs101ex/pkg/parhash"
)

var serveFlags struct {
	listenAddr  string
	backends    []string
	concurrency int
}

var serveCmd = cobra.Command{
	Use:   "serve",
	Short: "start the hasher service",
	Args:  cobra.NoArgs,
	Run:   serve,
}

func init() {
	f := serveCmd.Flags()
	f.StringVar(&serveFlags.listenAddr, "addr", "127.0.0.1:0", "listen addr")
	f.StringArrayVar(&serveFlags.backends, "backends", []string{}, "addresses of backends")
	f.IntVar(&serveFlags.concurrency, "concurrency", 4, "number of concurrent requests to backends")

	rootCmd.AddCommand(&serveCmd)
}

func serve(cmd *cobra.Command, args []string) {
	ctx, ctxCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer ctxCancel()

	s := parhash.New(parhash.Config{
		ListenAddr:   serveFlags.listenAddr,
		BackendAddrs: serveFlags.backends,
		Concurrency:  serveFlags.concurrency,
		Prom:         prometheus.DefaultRegisterer,
	})

	if err := s.Start(ctx); err != nil {
		log.Fatalf("failed to listen to %q: %v", serveFlags.listenAddr, err)
	}
	log.Printf("serving on %s", s.ListenAddr())

	<-ctx.Done()
	s.Stop()
}
