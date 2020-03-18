package core

/*
#cgo CFLAGS: -I./c/custom -I./c/include
#include "lwip/tcp.h"
#include <stdlib.h>
*/
import "C"
import (
	"sync"
	"unsafe"
)

var tcpConns sync.Map

// We need such a key-value mechanism because when passing a Go pointer
// to C, the Go pointer will only be valid during the call.
// If we pass a Go pointer to tcp_arg(), this pointer will not be usable
// in subsequent callbacks (e.g.: tcp_recv(), tcp_err()).
//
// Instead we need to pass a C pointer to tcp_arg(), we manually allocate
// the memory in C and return its pointer to Go code. After the connection
// end, the memory should be freed manually.
//
// See also:
// https://github.com/golang/go/issues/12416

// GoPointerSave save v(alue) and return the identifier unsafe.Pointer
func GoPointerSave(v interface{}) unsafe.Pointer {
	if v == nil {
		return nil
	}

	// Generates a real fake C pointer.
	// The pointer won't store any data but be used for indexing purposes.
	// As Go doesn't allow to cast a dangling pointer to "unsafe.Pointer", we do really allocate one byte.
	// Indexing is needed because Go doesn't allow C code to store pointers to Go data.
	var ptr unsafe.Pointer = C.malloc(C.size_t(1))
	if ptr == nil {
		panic("Can't allocate 'cgo-pointer hack index pointer': ptr == nil")
	}

	tcpConns.Store(ptr, v)

	return ptr
}

// GoPointerRestore retrive v(alue) via the identifier unsafe.Pointer
func GoPointerRestore(ptr unsafe.Pointer) (v interface{}, ok bool) {
	if ptr == nil {
		return nil, false
	}
	v, ok = tcpConns.Load(ptr)
	return
}

// GoPointerUnref remove and release identifier resource
func GoPointerUnref(ptr unsafe.Pointer) {
	if ptr == nil {
		return
	}

	tcpConns.Delete(ptr)

	C.free(ptr)
}
