package workgroup

import (
	"context"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	Sem *semaphore.Weighted
}

type Wg struct {
	sem *semaphore.Weighted

	wg sync.WaitGroup

	errLock sync.Mutex
	err     error
	nrErrs  int
}

func New(conf Config) *Wg {
	return &Wg{sem: conf.Sem}
}

func (wg *Wg) Go(ctx context.Context, do func(ctx context.Context) error) {
	wg.wg.Add(1)
	go func() {
		defer wg.wg.Done()

		err := wg.sem.Acquire(ctx, 1)
		if err != nil {
			wg.reportError(err)
			return
		}

		defer wg.sem.Release(1)

		err = do(ctx)
		if err != nil {
			wg.reportError(err)
		}
	}()
}

func (wg *Wg) reportError(err error) {
	wg.errLock.Lock()

	if wg.err == nil {
		wg.err = err
	}
	wg.nrErrs++

	wg.errLock.Unlock()
}

func (wg *Wg) Wait() error {
	wg.wg.Wait()

	// keep the race detector happy
	wg.errLock.Lock()
	defer wg.errLock.Unlock()

	if wg.nrErrs > 1 {
		wg.err = errors.Wrap(wg.err, "multiple errors in the workgroup")
	}
	return wg.err
}
