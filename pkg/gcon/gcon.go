package gcon

import (
	"context"
	"errors"
	"sync"
)

// from https://github.com/jonbodner/gcon

// Func represents any function that returns a Promise when passed to Run or Then.
type Func[T, V any] func(context.Context, T) (V, error)

// type FuncSame[V any] func(context.Context, V) (V, error)

var (
	// ErrIncomplete is returned when GetNow is invoked and the Func associated with the Promise hasn't completed.
	ErrIncomplete = errors.New("incomplete")
)

// Promise represents a potential or actual result from running a Func.
type Promise[V any] struct {
	val  V
	err  error
	done <-chan struct{}
}

// PromiseSet a struct holding a list of promises
type PromiseSet[V any] struct {
	Promises []*Promise[V]
}

// NewPromiseSet make a new promise set with an initialized promises slice
func NewPromiseSet[V any]() *PromiseSet[V] {
	ps := PromiseSet[V]{}
	ps.Promises = make([]*Promise[V], 0, 0)

	return &ps
}

// Add add one or more promises to promise set
func (promiseSet *PromiseSet[V]) Add(promises ...*Promise[V]) {
	for _, promise := range promises {
		promiseSet.Promises = append(promiseSet.Promises, promise)
	}
}

// Wait wait for all promises in promiseset to complete. Same as the Wait function but tied to a promise set
func (promiseSet *PromiseSet[V]) Wait() error {
	var wg sync.WaitGroup
	wg.Add(len(promiseSet.Promises))
	errChan := make(chan error, len(promiseSet.Promises))
	done := make(chan struct{})
	for _, p := range promiseSet.Promises {
		go func(p Promise[V]) {
			defer wg.Done()
			err := p.Wait()
			if err != nil {
				errChan <- err
			}
		}(*p)
	}
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case err := <-errChan:
		return err
	case <-done:
	}

	return nil
}

// Done check if work is done
func (promise *Promise[V]) Done() bool {
	select {
	case <-promise.done:
		return true
	default:
		return false
	}
}

// Get returns the value and the error (if any) for the Promise. Get waits until the Func associated with this
// Promise has completed. If the Func has completed, Get returns immediately.
func (promise *Promise[V]) Get() (V, error) {
	<-promise.done
	return promise.val, promise.err
}

// GetNow returns the value and the error (if any) for the Promise. If the Func associated with this Promise has
// not completed, GetNow returns the zero value for the return type and ErrIncomplete.
func (promise *Promise[V]) GetNow() (V, error) {
	select {
	case <-promise.done:
		return promise.val, promise.err
	default:
		var zero V
		return zero, ErrIncomplete
	}
}

// Run produces a Promise for the supplied Func, evaluating the supplied context.Context and data. The Promise is
// returned immediately, no matter how long it takes for the Func to complete processing.
func Run[T, V any](ctx context.Context, t T, f Func[T, V]) *Promise[V] {
	done := make(chan struct{})
	p := Promise[V]{
		done: done,
	}
	go func() {
		defer close(done)
		p.val, p.err = f(ctx, t)
	}()
	return &p
}

// Waiter defines an interface for the parameters to the Wait function.
type Waiter interface {
	Wait() error
}

// Wait allows a Promise to implement the Waiter interface. It is similar to Get, but only returns the error.
func (promise *Promise[V]) Wait() error {
	<-promise.done
	return promise.err
}

// Wait wait for a group of same type promises to complete
func Wait[V any](promises ...*Promise[V]) error {
	var wg sync.WaitGroup
	wg.Add(len(promises))
	errChan := make(chan error, len(promises))
	done := make(chan struct{})
	for _, p := range promises {
		go func(p Promise[V]) {
			defer wg.Done()
			err := p.Wait()
			if err != nil {
				errChan <- err
			}
		}(*p)
	}
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case err := <-errChan:
		return err
	case <-done:
	}
	return nil
}

// WaitAny takes in zero or more Waiter instances and paused until one returns an error or all of them complete
// successfully. It returns the first error from a Waiter or nil, if no Waiter returns an error.
func WaitAny(ws ...Waiter) error {
	var wg sync.WaitGroup
	wg.Add(len(ws))
	errChan := make(chan error, len(ws))
	done := make(chan struct{})
	for _, w := range ws {
		go func(w Waiter) {
			defer wg.Done()
			err := w.Wait()
			if err != nil {
				errChan <- err
			}
		}(w)
	}
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case err := <-errChan:
		return err
	case <-done:
	}
	return nil
}

// WithCancellation takes in a Func and returns a Func that implements the passed-in Func's behavior, but adds context
// cancellation.
func WithCancellation[T, V any](f Func[T, V]) Func[T, V] {
	return func(ctx context.Context, t T) (V, error) {
		done := make(chan struct{})
		var val V
		var err error
		go func() {
			defer close(done)
			val, err = f(ctx, t)
		}()
		select {
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err()
		case <-done:
		}
		return val, err
	}
}

// Then produces a Promise for the supplied Func, evaluating the supplied context.Context and Promise. The returned
// Promise is returned immediately, no matter how long it takes for the Func to complete processing. If the supplied
// Promise returns a non-nil error, the error is propagated to the returned Promise and the passed-in Func is not run.
func Then[T, V any](ctx context.Context, p *Promise[T], f Func[T, V]) *Promise[V] {
	done := make(chan struct{})
	promise := Promise[V]{
		done: done,
	}
	go func() {
		defer close(done)
		t, err := p.Get()
		if err != nil {
			promise.err = err
			return
		}
		v, err := f(ctx, t)
		promise.val = v
		promise.err = err
	}()

	return &promise
}

// ThenAll shows some of the possible shortcomings of promise chaining in that the arg and result needs to be of the
// same type.
// func ThenAll[V any](ctx context.Context, promise *Promise[V], functions ...FuncSame[V]) (result V, err error) {
// 	var arg V
// 	var wg = new(sync.WaitGroup)
// 	wg.Add(len(functions))
// 	for _, fun := range functions {
// 		arg, err = promise.Get()
// 		if err != nil {
// 			return
// 		}
// 		done := make(chan struct{})
// 		promise = &Promise[V]{
// 			done: done,
// 		}
// 		go func(fun FuncSame[V]) {
// 			defer close(done)
// 			defer wg.Done()
// 			result, err = fun(ctx, arg)
// 			if err != nil {
// 				return
// 			}
// 			promise.val = result
// 			promise.err = err
// 		}(fun)
// 	}

// 	wg.Wait()
// 	return result, err
// }
