package hash

import (
	"context"
	"crypto/sha256"
	"net"
	"sync"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	hashpb "fs101ex/pkg/gen/hashsvc"
)

type Config struct {
	ListenAddr string
}

type Server struct {
	conf Config

	stop context.CancelFunc
	l    net.Listener
	wg   sync.WaitGroup
}

func New(conf Config) *Server {
	return &Server{
		conf: conf,
	}
}

func (s *Server) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Wrapf(err, "Start()") }()

	ctx, s.stop = context.WithCancel(ctx)

	s.l, err = net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return err
	}

	srv := grpc.NewServer()
	hashpb.RegisterHashSvcServer(srv, s)

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()

		srv.Serve(s.l)
	}()
	go func() {
		defer s.wg.Done()

		<-ctx.Done()
		s.l.Close()
	}()

	return nil
}

func (s *Server) ListenAddr() string {
	return s.l.Addr().String()
}

func (s *Server) Stop() {
	s.stop()
	s.wg.Wait()
}

func (s *Server) Hash(ctx context.Context, req *hashpb.HashReq) (resp *hashpb.HashResp, err error) {
	h := sha256.Sum256(req.Data)
	return &hashpb.HashResp{Hash: h[:]}, nil
}
