// A spike, not part of hsmgate: what a SmartCard-HSM does over PC/SC with its own commands (ECDH, AES-CBC, AES-CMAC, HMAC-SHA256), with test keys made and removed here.
// The PIN is read from a file by this program and never printed.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"github.com/miekg/pkcs11"
)

const (
	aid         = "E82B0601040181C31F0201"
	idEC        = "5167c2"
	idAES       = "5167c1"
	opensc      = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
	cardcontact = "/tmp/libsc-hsm-pkcs11.so"
)

func must(err error, what string) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func readPIN(path string) []byte {
	b, err := os.ReadFile(path)
	must(err, "read the PIN file")
	return bytes.TrimSpace(b)
}

// ---- PC/SC

type cardConn struct {
	ctx  *scard.Context
	card *scard.Card
}

func connect() *cardConn {
	ctx, err := scard.EstablishContext()
	must(err, "PC/SC context")
	readers, err := ctx.ListReaders()
	must(err, "readers")
	if len(readers) == 0 {
		must(fmt.Errorf("no reader"), "readers")
	}
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	must(err, "connect")
	return &cardConn{ctx, card}
}

func (c *cardConn) close() {
	c.card.Disconnect(scard.LeaveCard) // never reset: another program has the card logged in
	c.ctx.Release()
}

func (c *cardConn) tx(apdu []byte) ([]byte, uint16) {
	resp, err := c.card.Transmit(apdu)
	must(err, "transmit")
	var out []byte
	for {
		if len(resp) < 2 {
			must(fmt.Errorf("short response"), "transmit")
		}
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		out = append(out, resp[:len(resp)-2]...)
		if sw>>8 == 0x61 { // more data
			resp, err = c.card.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, byte(sw & 0xff)})
			must(err, "get response")
			continue
		}
		return out, sw
	}
}

func apdu(cla, ins, p1, p2 byte, data []byte, le bool) []byte {
	a := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		a = append(a, byte(len(data)))
		a = append(a, data...)
	}
	if le {
		a = append(a, 0x00)
	}
	return a
}

func (c *cardConn) selectApplet() {
	id, _ := hex.DecodeString(aid)
	_, sw := c.tx(apdu(0x00, 0xA4, 0x04, 0x0C, id, false))
	if sw != 0x9000 {
		must(fmt.Errorf("SW %04x", sw), "select the applet")
	}
}

func (c *cardConn) verify(pin []byte) {
	_, sw := c.tx(apdu(0x00, 0x20, 0x00, 0x81, pin, false))
	if sw != 0x9000 {
		must(fmt.Errorf("SW %04x (not printing more)", sw), "verify the PIN")
	}
}

// keyRefs lists the one-byte references of the private and secret keys (files CCxx).
func (c *cardConn) keyRefs() []int {
	rsp, sw := c.tx(apdu(0x80, 0x58, 0x00, 0x00, nil, true))
	if sw != 0x9000 {
		must(fmt.Errorf("SW %04x", sw), "enumerate objects")
	}
	var refs []int
	for i := 0; i+1 < len(rsp); i += 2 {
		if rsp[i] == 0xCC {
			refs = append(refs, int(rsp[i+1]))
		}
	}
	sort.Ints(refs)
	return refs
}

// ---- PKCS#11

type p11 struct {
	ctx *pkcs11.Ctx
	sh  pkcs11.SessionHandle
}

func openP11(module string, pin []byte) *p11 {
	ctx := pkcs11.New(module)
	if ctx == nil {
		must(fmt.Errorf("cannot load %s", module), "module")
	}
	must(ctx.Initialize(), "initialize "+module)
	slots, err := ctx.GetSlotList(true)
	must(err, "slots")
	if len(slots) == 0 {
		must(fmt.Errorf("no token"), "slots")
	}
	sh, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	must(err, "open session")
	must(ctx.Login(sh, pkcs11.CKU_USER, string(pin)), "login")
	return &p11{ctx, sh}
}

func (p *p11) close() {
	p.ctx.Logout(p.sh)
	p.ctx.CloseSession(p.sh)
	p.ctx.Finalize()
	p.ctx.Destroy()
}

func (p *p11) destroyAll(idHex string) int {
	id, _ := hex.DecodeString(idHex)
	n := 0
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY, pkcs11.CKO_SECRET_KEY} {
		must(p.ctx.FindObjectsInit(p.sh, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class), pkcs11.NewAttribute(pkcs11.CKA_ID, id)}), "find")
		objs, _, err := p.ctx.FindObjects(p.sh, 10)
		p.ctx.FindObjectsFinal(p.sh)
		must(err, "find")
		for _, o := range objs {
			if err := p.ctx.DestroyObject(p.sh, o); err == nil {
				n++
			} else {
				fmt.Printf("  could not destroy an object of class %d: %v\n", class, err)
			}
		}
	}
	return n
}

func timeN(n int, f func()) []float64 {
	f() // one to warm up
	out := make([]float64, n)
	for i := range out {
		t := time.Now()
		f()
		out[i] = float64(time.Since(t).Microseconds()) / 1000
	}
	return out
}

func report(name string, ms []float64) {
	sorted := append([]float64{}, ms...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, v := range ms {
		sum += v
	}
	mean := sum / float64(len(ms))
	fmt.Printf("%-48s | %8.2f | %8.2f | %8.2f | %9.1f\n", name, mean, sorted[0], sorted[len(sorted)*95/100], 1000/mean)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: spike PINFILE make|test|clean")
		os.Exit(2)
	}
	pin := readPIN(os.Args[1])
	switch os.Args[2] {
	case "make":
		c := connect()
		c.selectApplet()
		before := c.keyRefs()
		c.close()
		// the EC key pair with OpenSC (it sets the rights from the attributes: derive)
		o := openP11(opensc, pin)
		id, _ := hex.DecodeString(idEC)
		ecparams, _ := hex.DecodeString("06082a8648ce3d030107")
		pub, _, err := o.ctx.GenerateKeyPair(o.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_ID, id), pkcs11.NewAttribute(pkcs11.CKA_LABEL, "spike-ec"), pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecparams), pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true)},
			[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_ID, id), pkcs11.NewAttribute(pkcs11.CKA_LABEL, "spike-ec"), pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true)})
		must(err, "generate the EC key pair")
		a, err := o.ctx.GetAttributeValue(o.sh, pub, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
		must(err, "read the public point")
		pt := a[0].Value
		if len(pt) == 67 && pt[0] == 4 && pt[1] == 0x41 {
			pt = pt[2:]
		}
		os.WriteFile("ecpoint.hex", []byte(hex.EncodeToString(pt)), 0o600)
		o.close()
		// the AES key with the vendor's module
		v := openP11(cardcontact, pin)
		aid_, _ := hex.DecodeString(idAES)
		_, err = v.ctx.GenerateKey(v.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)},
			[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_ID, aid_), pkcs11.NewAttribute(pkcs11.CKA_LABEL, "spike-aes"), pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true), pkcs11.NewAttribute(pkcs11.CKA_SIGN, true), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false)})
		must(err, "generate the AES key")
		v.close()
		c = connect()
		c.selectApplet()
		after := c.keyRefs()
		c.close()
		fmt.Println("key refs before:", before)
		fmt.Println("key refs after: ", after)
		have := map[int]bool{}
		for _, r := range before {
			have[r] = true
		}
		var added []int
		for _, r := range after {
			if !have[r] {
				added = append(added, r)
			}
		}
		fmt.Println("new key refs:", added)
		os.WriteFile("newrefs.txt", []byte(strings.Trim(fmt.Sprint(added), "[]")), 0o600)
	case "test":
		refsB, _ := os.ReadFile("newrefs.txt")
		var refs []int
		for _, f := range strings.Fields(string(refsB)) {
			var n int
			fmt.Sscan(f, &n)
			refs = append(refs, n)
		}
		ptHex, _ := os.ReadFile("ecpoint.hex")
		master, _ := hex.DecodeString(string(ptHex))
		c := connect()
		defer c.close()
		c.selectApplet()
		c.verify(pin)
		fmt.Println("selected the applet and verified the PIN over PC/SC")
		peer, _ := ecdh.P256().GenerateKey(rand.Reader)
		for _, ref := range refs {
			fmt.Printf("== key ref %d\n", ref)
			// ECDH (INS 62, algorithm 80)
			rsp, sw := c.tx(apdu(0x80, 0x62, byte(ref), 0x80, peer.PublicKey().Bytes(), true))
			if sw == 0x9000 {
				mp, _ := ecdh.P256().NewPublicKey(master)
				want, _ := peer.ECDH(mp)
				fmt.Printf("  ECDH ok, %d bytes (04 || X || Y of the result point); X equals the local ECDH secret: %v\n", len(rsp), len(rsp) >= 33 && bytes.Equal(rsp[1:33], want))
			} else {
				fmt.Printf("  ECDH: SW %04x\n", sw)
			}
			msg := bytes.Repeat([]byte("0123456789abcdef"), 2)
			for _, t := range []struct {
				name string
				algo byte
			}{{"AES-CMAC (18)", 0x18}, {"HMAC-SHA256 (99)", 0x99}} {
				r1, sw1 := c.tx(apdu(0x80, 0x78, byte(ref), t.algo, msg, true))
				r2, _ := c.tx(apdu(0x80, 0x78, byte(ref), t.algo, msg, true))
				r3, _ := c.tx(apdu(0x80, 0x78, byte(ref), t.algo, append(append([]byte{}, msg...), 'x'), true))
				if sw1 == 0x9000 {
					fmt.Printf("  %s: %d bytes, repeatable %v, differs for another message %v\n", t.name, len(r1), bytes.Equal(r1, r2), !bytes.Equal(r1, r3))
				} else {
					fmt.Printf("  %s: SW %04x\n", t.name, sw1)
				}
			}
			enc, sw := c.tx(apdu(0x80, 0x78, byte(ref), 0x10, msg, true))
			if sw == 0x9000 {
				dec, sw2 := c.tx(apdu(0x80, 0x78, byte(ref), 0x11, enc, true))
				fmt.Printf("  AES-CBC (10/11): %d bytes, round trip %v (SW %04x)\n", len(enc), bytes.Equal(dec, msg), sw2)
				// the card's CBC has a zero IV: the same two blocks give two different blocks, and the first block of the cipher text equals the encryption of block 1 alone
				one, _ := c.tx(apdu(0x80, 0x78, byte(ref), 0x10, msg[:16], true))
				fmt.Printf("  zero IV: the first block alone equals the first block of two: %v\n", bytes.Equal(one, enc[:16]))
			} else {
				fmt.Printf("  AES-CBC (10): SW %04x\n", sw)
			}
		}
	case "bench":
		refsB, _ := os.ReadFile("newrefs.txt")
		var refs []int
		for _, f := range strings.Fields(string(refsB)) {
			var n int
			fmt.Sscan(f, &n)
			refs = append(refs, n)
		}
		ecRef, aesRef := byte(refs[0]), byte(refs[1])
		peer, _ := ecdh.P256().GenerateKey(rand.Reader)
		peerPt := peer.PublicKey().Bytes()
		msg32 := bytes.Repeat([]byte("0123456789abcdef"), 2)
		msg64 := bytes.Repeat([]byte("0123456789abcdef"), 4)
		const N = 40
		fmt.Println("each line: operation | mean ms | min | p95 | per second (one caller, one after another)")
		// raw PC/SC
		c := connect()
		c.selectApplet()
		c.verify(pin)
		report("PC/SC raw   ECDH (80 62)", timeN(N, func() { c.tx(apdu(0x80, 0x62, ecRef, 0x80, peerPt, true)) }))
		report("PC/SC raw   AES-CMAC 32 B (78/18)", timeN(N, func() { c.tx(apdu(0x80, 0x78, aesRef, 0x18, msg32, true)) }))
		report("PC/SC raw   HMAC-SHA256 32 B (78/99)", timeN(N, func() { c.tx(apdu(0x80, 0x78, aesRef, 0x99, msg32, true)) }))
		report("PC/SC raw   AES-CBC enc 64 B (78/10)", timeN(N, func() { c.tx(apdu(0x80, 0x78, aesRef, 0x10, msg64, true)) }))
		report("PC/SC raw   AES-CBC dec 64 B (78/11)", timeN(N, func() { c.tx(apdu(0x80, 0x78, aesRef, 0x11, msg64, true)) }))
		c.close()
		// PKCS#11 with OpenSC: what hsmgate does for an ECDH
		o := openP11(opensc, pin)
		id, _ := hex.DecodeString(idEC)
		must(o.ctx.FindObjectsInit(o.sh, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY), pkcs11.NewAttribute(pkcs11.CKA_ID, id)}), "find")
		objs, _, err := o.ctx.FindObjects(o.sh, 1)
		o.ctx.FindObjectsFinal(o.sh)
		must(err, "find")
		prv := objs[0]
		derive := func() {
			k, err := o.ctx.DeriveKey(o.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPt))}, prv,
				[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET), pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true)})
			must(err, "derive")
			o.ctx.GetAttributeValue(o.sh, k, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
			o.ctx.DestroyObject(o.sh, k)
		}
		report("PKCS#11 OpenSC ECDH1_DERIVE (hsmgate today)", timeN(N, derive))
		o.close()
		// PKCS#11 with the vendor's module
		v := openP11(cardcontact, pin)
		aid_, _ := hex.DecodeString(idAES)
		must(v.ctx.FindObjectsInit(v.sh, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_ID, aid_)}), "find")
		objs, _, err = v.ctx.FindObjects(v.sh, 1)
		v.ctx.FindObjectsFinal(v.sh)
		must(err, "find AES")
		sk := objs[0]
		report("PKCS#11 vendor  AES-CMAC 32 B", timeN(N, func() {
			must(v.ctx.SignInit(v.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CMAC, nil)}, sk), "signinit")
			_, err := v.ctx.Sign(v.sh, msg32)
			must(err, "sign")
		}))
		iv := make([]byte, 16)
		report("PKCS#11 vendor  AES-CBC enc 64 B", timeN(N, func() {
			must(v.ctx.EncryptInit(v.sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}, sk), "encinit")
			_, err := v.ctx.Encrypt(v.sh, msg64)
			must(err, "enc")
		}))
		v.close()
		// software, for comparison
		report("software    ECDH P-256 (Go)", timeN(2000, func() { k, _ := ecdh.P256().GenerateKey(rand.Reader); k.ECDH(peer.PublicKey()) }))
	case "clean":
		o := openP11(opensc, pin)
		n := o.destroyAll(idEC)
		o.close()
		v := openP11(cardcontact, pin)
		m := v.destroyAll(idAES)
		v.close()
		fmt.Printf("destroyed %d objects of the EC key and %d of the AES key\n", n, m)
		c := connect()
		c.selectApplet()
		fmt.Println("key refs on the card now:", c.keyRefs())
		c.close()
		os.Remove("ecpoint.hex")
		os.Remove("newrefs.txt")
	}
}
