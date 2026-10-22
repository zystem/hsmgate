package peer

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestAddr(t *testing.T) {
	for r, want := range map[string]string{"[fe80::1%eth0]:5555": "fe80::1", "[::ffff:10.1.2.3]:1": "10.1.2.3", "127.0.0.1:9": "127.0.0.1", "garbage": ""} {
		a := Addr(&http.Request{RemoteAddr: r})
		if want == "" && a.IsValid() || want != "" && (a.String() != want || a.Zone() != "") {
			t.Errorf("%q: %v", r, a)
		}
	}
	if !Allowed([]netip.Prefix{netip.MustParsePrefix("fe80::/10")}, Addr(&http.Request{RemoteAddr: "[fe80::1%eth0]:5"})) ||
		!Allowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Addr(&http.Request{RemoteAddr: "[::ffff:10.1.2.3]:1"})) ||
		Allowed([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Addr(&http.Request{RemoteAddr: "11.0.0.1:1"})) {
		t.Error("Allowed")
	}
}

func TestFailuresBlockAnAddressForAWindow(t *testing.T) {
	f := NewFailures()
	a := netip.MustParseAddr("192.0.2.1")
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for i := 0; i < Limit-1; i++ {
		f.Add(a, now)
	}
	if f.Blocked(a, now) {
		t.Fatal("blocked too early")
	}
	f.Add(a, now)
	if !f.Blocked(a, now) || f.Blocked(netip.MustParseAddr("192.0.2.2"), now) {
		t.Fatal("the address was not blocked, or another one was")
	}
	if f.Blocked(a, now.Add(Window+time.Second)) {
		t.Error("still blocked after the window")
	}
	var nilF *Failures
	nilF.Add(a, now)
	if nilF.Blocked(a, now) {
		t.Error("a nil Failures blocked")
	}
}
