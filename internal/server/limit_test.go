package server

import (
	"net"
	"testing"
	"time"
)

// With a limit of 2 the third connection is accepted only when one of the first two is closed.
func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(inner, 2)
	defer l.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var clients []net.Conn
	for i := 0; i < 3; i++ {
		clients = append(clients, dial())
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	c1, c2 := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted over the limit")
	case <-time.After(200 * time.Millisecond):
	}
	c1.Close()
	c1.Close() // closing twice gives back only one place
	select {
	case c3 := <-accepted:
		c3.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the third connection was not accepted after one closed")
	}
	c2.Close()
}
