package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"

	hashpb "fs101ex/pkg/gen/hashsvc"
	"fs101ex/pkg/workgroup"
)

var sumFlags struct {
	addr string
}

var sumCmd = cobra.Command{
	Use:   "sum <file0> <file1> ...",
	Short: "compute sha256 sum of short files",
	Run:   sum,
}

func init() {
	f := sumCmd.Flags()
	f.StringVar(&sumFlags.addr, "addr", "", "address of the hasher service")

	rootCmd.AddCommand(&sumCmd)
}

func sum(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if sumFlags.addr == "" {
		log.Fatalf("--addr must be provided")
	}

	conn, err := grpc.Dial(sumFlags.addr,
		grpc.WithInsecure(), /* allow non-TLS connections */
	)
	if err != nil {
		log.Fatalf("failed to connect to %q: %v", sumFlags.addr, err)
	}
	defer conn.Close()

	client := hashpb.NewHashSvcClient(conn)

	var (
		wg     = workgroup.New(workgroup.Config{Sem: semaphore.NewWeighted(8)})
		hashes = make(map[string]string)
		lock   sync.Mutex
	)
	for i := range args {
		fileName := args[i]

		wg.Go(ctx, func(ctx context.Context) (err error) {
			f, err := os.Open(fileName)
			if err != nil {
				return err
			}
			defer f.Close()

			st, err := f.Stat()
			if err != nil {
				return err
			}

			if st.Size() > 1024*1024 {
				return errors.Errorf("file is too big: %q", fileName)
			}

			data, err := io.ReadAll(f)
			if err != nil {
				return err
			}

			resp, err := client.Hash(ctx, &hashpb.HashReq{Data: data})
			if err != nil {
				return err
			}

			lock.Lock()
			hashes[fileName] = hex.EncodeToString(resp.Hash)
			lock.Unlock()

			return nil
		})
	}
	if err := wg.Wait(); err != nil {
		log.Fatalf("failed to hash files: %v", err)
	}

	for fileName, hash := range hashes {
		fmt.Printf("%s  %s\n", hash, fileName)
	}
}
