package core

/*
#cgo CFLAGS: -I./c/custom -I./c/include
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
*/
import "C"
import (
	"log"
	"sync"
	"time"
	"unsafe"
)

const CHECK_TIMEOUTS_INTERVAL = 250 // in millisecond
const TCP_POLL_INTERVAL = 8         // poll every 4 seconds

type LWIPStack interface {
	Write([]byte) (int, error)
	Close() error
	RestartTimeouts()
}

// lwIP runs in a single thread, locking is needed in Go runtime.
var lwipMutex = &sync.Mutex{}

type lwipStack struct {
	tpcb            *C.struct_tcp_pcb
	upcb            *C.struct_udp_pcb
	timeoutStopChan chan bool
}

// NewLWIPStack listens for any incoming connections/packets and registers
// corresponding accept/recv callback functions.
func NewLWIPStack() LWIPStack {
	tcpPCB := C.tcp_new_ip_type(C.IPADDR_TYPE_V4)
	if tcpPCB == nil {
		panic("tcp_new return nil")
	}

	err := C.tcp_bind(tcpPCB, C.IP_ADDR_ANY, 0)
	switch err {
	case C.ERR_OK:
		break
	case C.ERR_VAL:
		panic("invalid PCB state")
	case C.ERR_USE:
		panic("port in use")
	default:
		C.memp_free(C.MEMP_TCP_PCB, unsafe.Pointer(tcpPCB))
		panic("unknown tcp_bind return value")
	}

	tcpPCB = C.tcp_listen_with_backlog(tcpPCB, C.TCP_DEFAULT_LISTEN_BACKLOG)
	if tcpPCB == nil {
		panic("can not allocate tcp pcb")
	}

	setTCPAcceptCallback(tcpPCB)

	udpPCB := C.udp_new()
	if udpPCB == nil {
		panic("could not allocate udp pcb")
	}

	err = C.udp_bind(udpPCB, C.IP_ADDR_ANY, 0)
	if err != C.ERR_OK {
		panic("address already in use")
	}

	setUDPRecvCallback(udpPCB, nil)
	c := make(chan bool)
	go func(c <-chan bool) {
		var ok bool
	Loop:
		for {
			select {
			case _, ok = <-c:
				if !ok {
					log.Printf("got sys_check_timeouts stop signal")
					break Loop
				}
			case <-time.After(CHECK_TIMEOUTS_INTERVAL * time.Millisecond):
				lwipMutex.Lock()
				C.sys_check_timeouts()
				lwipMutex.Unlock()
			}
		}
	}(c)

	return &lwipStack{
		tpcb:            tcpPCB,
		upcb:            udpPCB,
		timeoutStopChan: c,
	}
}

func (s *lwipStack) Write(data []byte) (int, error) {
	return Input(data)
}

func (s *lwipStack) RestartTimeouts() {
	C.sys_restart_timeouts()
}

func (s *lwipStack) Close() error {
	tcpConns.Range(func(_, c interface{}) bool {
		c.(*tcpConn).Abort()
		return true
	})
	udpConns.Range(func(_, c interface{}) bool {
		c.(*udpConn).Close()
		return true
	})

	// free TCP listener pcb
	err := C.tcp_close(s.tpcb)
	switch err {
	case C.ERR_OK:
		// ERR_OK if connection has been closed
		break
	case C.ERR_ARG:
		// invalid pointer or state
		panic("listen tpcb is invalid")
	default:
		// another err_t if closing failed and pcb is not freed
		// make sure free is invoked
		C.tcp_abort(s.tpcb)
	}

	// free UDP pcb
	C.udp_remove(s.upcb)

	// stop timeout check goroutine
	// must be the last step
	close(s.timeoutStopChan)

	return nil
}

func init() {
	// Initialize lwIP.
	//
	// There is a little trick here, a loop interface (127.0.0.1)
	// is created in the initialization stage due to the option
	// `#define LWIP_HAVE_LOOPIF 1` in `lwipopts.h`, so we need
	// not create our own interface.
	//
	// Now the loop interface is just the first element in
	// `C.netif_list`, i.e. `*C.netif_list`.
	lwipInit()

	// Set MTU.
	C.netif_list.mtu = 1500
}
