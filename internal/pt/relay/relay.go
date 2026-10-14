// Package relay copies bytes between two connections.
package relay

import (
	"io"
	"sync"
)

const bufSize = 32 << 10

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufSize)
		return &b
	},
}

// Pipe copies data both ways between a and b. It returns after both
// directions have stopped and closes both connections.
//
// When one direction ends, for example because a peer closed, Pipe closes
// both connections so the other direction unblocks. Tor treats a closed link
// as the end of the circuit, so a half-open state has no use here.
func Pipe(a, b io.ReadWriteCloser) {
	var (
		wg   sync.WaitGroup
		once sync.Once
	)
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	copyDir := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		buf := bufPool.Get().(*[]byte)
		defer bufPool.Put(buf)
		_, _ = io.CopyBuffer(dst, src, *buf)
		once.Do(closeBoth)
	}
	wg.Add(2)
	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()
}
