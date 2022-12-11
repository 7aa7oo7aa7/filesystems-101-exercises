package main

import (
	"context"
	"fs101ex/pkg/hash"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var serveFlags struct {
	listenAddr string
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

	rootCmd.AddCommand(&serveCmd)
}

func serve(cmd *cobra.Command, args []string) {
	ctx, ctxCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer ctxCancel()

	s := hash.New(hash.Config{
		ListenAddr: serveFlags.listenAddr,
	})

	if err := s.Start(ctx); err != nil {
		log.Fatalf("failed to listen to %q: %v", serveFlags.listenAddr, err)
	}
	log.Printf("serving on %s", s.ListenAddr())

	<-ctx.Done()
	s.Stop()
}
