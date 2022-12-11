package parhash

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"

	hashpb "fs101ex/pkg/gen/hashsvc"
	parhashpb "fs101ex/pkg/gen/parhashsvc"
	"fs101ex/pkg/workgroup"
)

type Config struct {
	ListenAddr   string
	BackendAddrs []string
	Concurrency  int
}

// Implement a server that responds to ParallelHash()
// as declared in /proto/parhash.proto.
//
// The implementation of ParallelHash() must not hash the content
// of buffers on its own. Instead, it must send buffers to backends
// to compute hashes. Buffers must be fanned out to backends in the
// round-robin fashion.
//
// For example, suppose that 2 backends are configured and ParallelHash()
// is called to compute hashes of 5 buffers. In this case it may assign
// buffers to backends in this way:
//
//	backend 0: buffers 0, 2, and 4,
//	backend 1: buffers 1 and 3.
//
// Requests to hash individual buffers must be issued concurrently.
// Goroutines that issue them must run within /pkg/workgroup/Wg. The
// concurrency within workgroups must be limited by Server.sem.
//
// WARNING: requests to ParallelHash() may be concurrent, too.
// Make sure that the round-robin fanout works in that case too,
// and evenly distributes the load across backends.
type Server struct {
	conf Config

	sem *semaphore.Weighted

	l          net.Listener
	wg         sync.WaitGroup
	stop       context.CancelFunc
	mutex      sync.Mutex
	curBackend int
}

func New(conf Config) *Server {
	return &Server{
		conf: conf,
		sem:  semaphore.NewWeighted(int64(conf.Concurrency)),
	}
}

func (s *Server) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Wrap(err, "Start()") }()

	s.l, err = net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return err
	}

	ctx, s.stop = context.WithCancel(ctx)

	srv := grpc.NewServer()
	parhashpb.RegisterParallelHashSvcServer(srv, s)

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

func (s *Server) ParallelHash(ctx context.Context, req *parhashpb.ParHashReq) (resp *parhashpb.ParHashResp, err error) {
	defer func() { err = errors.Wrapf(err, "ParallelHash()") }()

	countBackends := len(s.conf.BackendAddrs)
	clients := make([]hashpb.HashSvcClient, countBackends)
	conns := make([]*grpc.ClientConn, countBackends)
	wg := workgroup.New(workgroup.Config{Sem: s.sem})

	for i, addr := range s.conf.BackendAddrs {
		conns[i], err = grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("Cannot connect: %v", err)
		}
		defer conns[i].Close()
		clients[i] = hashpb.NewHashSvcClient(conns[i])
	}

	hashes := make([][]byte, len(req.Data))

	for i, data := range req.Data {
		cur_i := i
		cur_data := data

		wg.Go(ctx, func(ctx context.Context) error {
			s.mutex.Lock()
			curBackend := s.curBackend
			s.curBackend = (s.curBackend + 1) % countBackends
			s.mutex.Unlock()

			backendResp, err := clients[curBackend].Hash(ctx, &hashpb.HashReq{Data: cur_data})
			if err != nil {
				return err
			}

			s.mutex.Lock()
			hashes[cur_i] = backendResp.Hash
			s.mutex.Unlock()

			return nil
		})
	}

	err = wg.Wait()
	if err != nil {
		log.Fatalf("Cannot hash data: %v", err)
	}

	return &parhashpb.ParHashResp{Hashes: hashes}, nil
}
