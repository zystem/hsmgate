package card

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// explorerConn sends commands to a card through one run of `opensc-explorer` that is fed on its standard input. The card is selected once and stays so for the whole run, which a
// login needs (every run of a tool that connects ends the login), and the PIN goes down a pipe: it is never in the arguments of a command line, where another user of the machine
// could read it. The program only moves bytes: the commands are made here.
type explorerConn struct {
	in    io.WriteCloser
	lines chan string
	done  chan error
	wait  func() error
	mu    sync.Mutex
}

// Starter starts a program with its standard input and output as pipes (the output carries the error output too) and says how to wait for it to end. OpenExplorer uses a real
// program; a test gives a card made of bytes.
type Starter func(ctx context.Context, name string, args ...string) (stdin io.WriteCloser, stdout io.Reader, wait func() error, err error)

// execStarter starts a real program.
func execStarter(ctx context.Context, name string, args ...string) (io.WriteCloser, io.Reader, func() error, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- opensc-explorer and a reader number made by this tool
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	go func() { pw.CloseWithError(cmd.Wait()) }()
	return in, pr, func() error { return nil }, nil
}

// OpenExplorer connects to the card in a reader. start is how to start opensc-explorer (nil: the real program).
func OpenExplorer(ctx context.Context, start Starter, r Reader) (Conn, error) {
	if start == nil {
		start = execStarter
	}
	in, out, wait, err := start(ctx, "opensc-explorer", "-r", strconv.Itoa(r.Nr))
	if err != nil {
		return nil, noTool(err)
	}
	c := &explorerConn{in: in, lines: make(chan string, 256), done: make(chan error, 1), wait: wait}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()
	// the program prints its greeting (and "Using reader with a card", or an error such as "No smart card readers found")
	deadline := time.After(20 * time.Second)
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				return nil, errors.New("opensc-explorer ended before it was ready")
			}
			if strings.Contains(l, "No smart card readers found") || strings.Contains(l, "Failed to connect") || strings.Contains(l, "Card not present") {
				c.Close()
				return nil, fmt.Errorf("opensc-explorer: %s", strings.TrimSpace(l))
			}
			if strings.HasPrefix(l, "OpenSC Explorer") || strings.HasPrefix(l, "Using reader") { // the prompt has no end of line, so it is not waited for
				return c, nil
			}
		case <-deadline:
			c.Close()
			return nil, errors.New("opensc-explorer did not start in 20 seconds")
		}
	}
}

// Transmit sends one command (an APDU) and returns the answer with the status word at the end.
func (c *explorerConn) Transmit(apdu []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make([]string, len(apdu))
	for i, b := range apdu {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	if _, err := io.WriteString(c.in, "apdu "+strings.Join(parts, ":")+"\n"); err != nil {
		return nil, err
	}
	var got []string
	timeout := time.After(3 * time.Minute) // a key of 4096 bits takes the card up to a minute and more
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				return nil, fmt.Errorf("opensc-explorer ended: %s", strings.TrimSpace(strings.Join(got, " ")))
			}
			got = append(got, l)
			// the line that ends an answer: "Success!" when the status is 9000, "Failure: …" for any other, or a complaint about the command itself
			if l == "Success!" || strings.HasPrefix(l, "Failure") || strings.HasPrefix(l, "Wrong") || strings.HasPrefix(l, "Invalid") || strings.HasPrefix(l, "Usage:") {
				return answerOf(got)
			}
		case <-timeout:
			return nil, errors.New("the card did not answer in 3 minutes")
		}
	}
}

// answerOf makes the answer from the lines that the program printed for one command.
func answerOf(lines []string) ([]byte, error) {
	var from int = -1
	for i, l := range lines {
		if strings.HasPrefix(l, "Sending:") {
			from = i
			break
		}
	}
	if from < 0 {
		return nil, fmt.Errorf("the card did not get the command: %s", strings.TrimSpace(strings.Join(lines, " ")))
	}
	rs, err := parseExchange(strings.Join(lines[from:], "\n"))
	if err != nil || len(rs) != 1 {
		return nil, fmt.Errorf("cannot read the answer of the card: %v", lines)
	}
	return append(rs[0].Data, byte(rs[0].SW>>8), byte(rs[0].SW)), nil // #nosec G115 -- the two bytes of a status word
}

func (c *explorerConn) Close() error {
	// "quit", then the end of the input; a program that is not reading is not waited for
	done := make(chan struct{})
	go func() {
		_, _ = io.WriteString(c.in, "quit\n")
		_ = c.in.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = c.in.Close()
	}
	return nil
}
