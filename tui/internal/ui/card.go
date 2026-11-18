package ui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/tui/internal/card"
	"github.com/zystem/hsmgate/tui/internal/sys"
)

// cardState is what the Card page remembers between visits: the tree that was read, and the reader that was chosen (-1: the first one with a card).
type cardState struct {
	tree    *card.Tree
	reader  int
	err     string
	busy    bool
	writeOK bool   // the person has said that a command that changes the card may go on while the service holds it
	redraw  func() // draws the page again (set by the page)
	cursor  int    // the line the person was on, as its position in the tree: after the card is read again the page stands on it
}

func (a *App) cardRun() card.Run {
	if a.opt.CardRun != nil {
		return a.opt.CardRun
	}
	return sys.Run
}

// cardView is the tree of a SmartCard-HSM, as a card manager shows it: the PINs and their tries, the key domains with the key check value of their DKEK, the keys in them; on the
// right, what the selected line means. It only reads.
func (a *App) cardView() tview.Primitive {
	st := &a.card
	tree := tview.NewTreeView()
	tree.SetBorder(true).SetTitle(" the card ")
	tree.SetGraphics(false)
	tree.SetSelectedFunc(func(n *tview.TreeNode) { // Enter: what can be done with the line
		if n.GetReference() != nil {
			a.cardMenu(n.GetReference())
		}
	})

	detail := tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	detail.SetBorder(true).SetTitle(" what it is (PgUp, PgDn) ")

	show := func(n *tview.TreeNode) {
		if n == nil || n.GetReference() == nil {
			return // a line that is only a message: the text beside it stays
		}
		detail.SetText(a.cardDetail(n.GetReference()))
		detail.ScrollToBeginning()
	}
	tree.SetChangedFunc(func(n *tview.TreeNode) {
		show(n)
		if st.tree != nil && !st.busy && st.err == "" { // not while the page shows only a message
			st.cursor = nodePosition(tree.GetRoot(), n)
		}
	})

	fill := func() {
		tree.SetTitle(" the card ")
		root := tview.NewTreeNode("no card read yet").SetColor(tcell.ColorBlack)
		switch {
		case st.busy:
			root.SetText("reading the card…")
		case st.err != "":
			root.SetText("the card could not be read")
			detail.SetText("[red]" + tview.Escape(st.err) + "[black]")
		case st.tree != nil:
			root = a.cardNodes(st.tree)
			tree.SetTitle(fmt.Sprintf(" the card (reader %d) ", st.tree.Reader.Nr))
		default:
			detail.SetText("Press [::b]Read the card[::-] (or R): the page asks the card what it holds, with commands that only read. No PIN is sent and nothing is written. Then Enter on a line (or [::b]Actions[::-]) lists what can be done with it: PINs, key domains, DKEK shares, keys, backup files.\n\n" +
				"The card is the one in the first reader that has a card; [::b]Reader[::-] chooses another.\n\nIt needs the program opensc-tool (the package opensc).")
		}
		tree.SetRoot(root)
		cur := nodeAt(root, st.cursor)
		tree.SetCurrentNode(cur)
		show(cur)
	}
	st.redraw = fill
	fill()

	read := func() { a.cardRead(fill) }
	tree.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyRune && (ev.Rune() == 'r' || ev.Rune() == 'R'):
			read()
			return nil
		case ev.Key() == tcell.KeyPgDn || ev.Key() == tcell.KeyPgUp: // the right side may be longer than its box
			row, _ := detail.GetScrollOffset()
			step := 5
			if ev.Key() == tcell.KeyPgUp {
				step = -5
			}
			if row+step < 0 {
				step = -row
			}
			detail.ScrollTo(row+step, 0)
			return nil
		}
		return ev
	})
	// the lines of the tree are long: side by side on a wide screen, one above the other on a console of 80 columns
	body := tview.NewFlex()
	if a.sw > 0 && a.sw < 120 {
		body.SetDirection(tview.FlexRow).AddItem(tree, 0, 3, true).AddItem(detail, 0, 2, false)
	} else {
		body.AddItem(tree, 0, 3, true).AddItem(detail, 0, 2, false)
	}
	return a.page("Card: what a SmartCard-HSM holds", body,
		btn("Read the card", read),
		btn("Actions", func() {
			if n := tree.GetCurrentNode(); n != nil && n.GetReference() != nil {
				a.cardMenu(n.GetReference())
			}
		}),
		btn("Reader", func() { a.cardChooseReader(read) }))
}

// nodePosition is the place of a line in the tree, counted from the top (0 is the card). Walk goes on to the other lines when its function says false, so a flag stops the count.
func nodePosition(root, n *tview.TreeNode) int {
	pos, found := 0, -1
	root.Walk(func(node, _ *tview.TreeNode) bool {
		if found >= 0 {
			return false
		}
		if node == n {
			found = pos
			return false
		}
		pos++
		return true
	})
	return found
}

// nodeAt is the line at a place in the tree (the card when there is no such place).
func nodeAt(root *tview.TreeNode, pos int) *tview.TreeNode {
	var cur *tview.TreeNode
	i := 0
	root.Walk(func(node, _ *tview.TreeNode) bool {
		if cur != nil {
			return false
		}
		if i == pos {
			cur = node
			return false
		}
		i++
		return true
	})
	if cur == nil {
		return root
	}
	return cur
}

// cardNodes makes the tree: the card, the PINs, the key domains with their keys.
func (a *App) cardNodes(t *card.Tree) *tview.TreeNode {
	title := t.Label
	if title == "" {
		title = "SmartCard-HSM"
	}
	if t.DeviceID != "" {
		title += " (" + t.DeviceID + ")"
	}
	root := tview.NewTreeNode(title).SetReference(t).SetColor(tcell.ColorDarkBlue).SetSelectable(true)
	pinNode := func(p card.PIN) {
		c := tcell.ColorBlack
		if p.Blocked {
			c = tcell.ColorDarkRed
		} else if p.Tries >= 0 && p.Tries <= 1 {
			c = tcell.ColorDarkRed
		}
		root.AddChild(tview.NewTreeNode(p.Text()).SetReference(p).SetColor(c))
	}
	pinNode(t.UserPIN)
	pinNode(t.SOPIN)
	for _, d := range t.Domains {
		if !d.Created {
			root.AddChild(tview.NewTreeNode(fmt.Sprintf("Key domain %d not created", d.Number)).SetReference(d).SetColor(tcell.ColorGray))
			continue
		}
		text := domainText(d)
		n := tview.NewTreeNode(text).SetReference(d).SetColor(tcell.ColorDarkBlue).SetExpanded(true)
		for _, k := range d.Keys {
			n.AddChild(tview.NewTreeNode(keyText(k)).SetReference(k))
		}
		root.AddChild(n)
	}
	if len(t.Loose) > 0 {
		n := tview.NewTreeNode("keys in no key domain").SetColor(tcell.ColorGray).SetExpanded(true)
		for _, k := range t.Loose {
			n.AddChild(tview.NewTreeNode(keyText(k)).SetReference(k))
		}
		root.AddChild(n)
	}
	root.SetExpanded(true)
	return root
}

// domainText is the line of a created key domain, in the words of the card manager: a DKEK with its check value, a DKEK still being set up, or an XKEK in a key domain.
func domainText(d card.Domain) string {
	var text string
	switch {
	case d.XKEK:
		text = fmt.Sprintf("XKEK with KCV %s in key domain %s", d.KCV, d.DomainID)
	case d.Outstanding > 0:
		text = fmt.Sprintf("DKEK set-up in progress with %d of %d shares missing", d.Outstanding, d.Shares)
	default:
		text = "DKEK with KCV " + d.KCV
	}
	if d.Label != "" {
		text += " (" + d.Label + ")"
	}
	return text
}

func keyText(k card.Key) string {
	label := k.Label
	if label == "" {
		label = "key"
	}
	algo := k.Algo
	if algo == "" {
		algo = "?"
	}
	return fmt.Sprintf("%s (%d, %s)", label, k.ID, algo)
}

// cardDetail says in words what a line of the tree is.
func (a *App) cardDetail(ref any) string {
	switch v := ref.(type) {
	case *card.Tree:
		s := fmt.Sprintf("[::b]%s[::-]\n\nreader: %s\nSmartCard-HSM version %s, platform %d\nfree memory: %d bytes\n\n", tview.Escape(orStr(v.Label, "(no label)")), tview.Escape(v.Reader.Name), v.Version, v.Platform, v.FreeMemory)
		s += "The line under the card name is the PINs, then the key domains, with the keys in them.\n\n"
		s += "Enter on a line (or the Actions button) shows what can be done with it. Reading changes nothing; the actions that change the card ask for the PIN and say what they do. Making a key on the card and XKEK domains are not on this page yet: use the vendor's card manager or sc-hsm-tool and pkcs11-tool (docs/tokens/smartcard-hsm.md)."
		return s
	case card.PIN:
		return a.pinDetail(v)
	case card.Domain:
		return a.domainDetail(v)
	case card.Key:
		return a.keyDetail(v)
	}
	return ""
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (a *App) pinDetail(p card.PIN) string {
	var s string
	if p.Name == "User PIN" {
		s = "[::b]User PIN[::-]: the PIN that opens the card for use. hsmgate is given it once when it starts (a PIN file, [::b]pin_file[::-]) or by Unlock on the Tokens page (`hsmgate unlock`); the service never tries a PIN that the card refused.\n\n"
	} else {
		s = "[::b]SO PIN[::-] (security officer): unblocks the User PIN and initializes the card. Keep it apart from the User PIN; it is not used by the service.\n\n"
	}
	switch {
	case p.Verified:
		s += "The card is [::b]open[::-] now: a program has given this PIN and the card has not been reset since."
	case p.Blocked:
		s += "[red]Blocked[black]: no tries are left. A blocked User PIN is unblocked with the SO PIN (`sc-hsm-tool`); a blocked SO PIN cannot be."
	case p.Tries >= 0:
		s += fmt.Sprintf("Not given in this session. [::b]%d[::-] tries remain (the card said %04X). A wrong PIN uses one try; when none is left the PIN is blocked. Do not try a PIN you are not sure of.", p.Tries, p.SW)
	default:
		s += fmt.Sprintf("The card answered %04X, which is not a state this page knows.", p.SW)
	}
	return s
}

func (a *App) domainDetail(d card.Domain) string {
	if !d.Created {
		return fmt.Sprintf("[::b]Key domain %d[::-] is not created. A key domain is a group of keys that share one key encryption key (DKEK). Enter makes one: you say how many shares its DKEK is made of, and import the shares afterwards.", d.Number)
	}
	s := fmt.Sprintf("[::b]Key domain %d[::-]", d.Number)
	if d.Label != "" {
		s += " " + tview.Escape(d.Label)
	}
	s += "\n\n"
	switch {
	case d.XKEK:
		s += fmt.Sprintf("This key domain has an [::b]XKEK[::-] (exchange key encryption key), not a DKEK made of shares. Key check value (KCV): [::b]%s[::-]; the key domain it is in: [::b]%s[::-].\n\n", d.KCV, d.DomainID)
		s += "The card manager makes it with its \"Create XKEK Key Domain\", \"Derive XKEK\" and \"Associate XKEK Key Domain\" actions: the key encryption key is not typed in as shares but derived with ECDH, and keys can then be wrapped to a card of another key domain. This page shows it and does not make or change one. (Reading an XKEK domain was tested only on a card made of bytes, not on a real card.)"
	case d.Outstanding > 0:
		s += fmt.Sprintf("The DKEK is [::b]being set up[::-]: %d share(s) in all, [red]%d still to import[black]. Keys cannot be wrapped or unwrapped in this domain until the last share is in. KCV so far: %s.\n\n", d.Shares, d.Outstanding, d.KCV)
		s += "A DKEK (device key encryption key) is made of shares: each share is made on a computer (or a card manager) and imported into the card; when the last one is in, the card has the key. Import the remaining shares with sc-hsm-tool (docs/tokens/smartcard-hsm.md)."
	default:
		s += fmt.Sprintf("DKEK: %d share(s), all imported.\nKey check value (KCV): [::b]%s[::-]\n\n", d.Shares, d.KCV)
		s += "A key domain is a group of keys that share one key encryption key. Here it is a DKEK (device key encryption key), made of shares that were imported into the card. The KCV is a short check of that key: two cards with the same KCV can pass wrapped keys to each other, which is how a spare card gets a copy of a key (docs/operations.md, \"spare card\")."
	}
	return s
}

func (a *App) keyDetail(k card.Key) string {
	s := fmt.Sprintf("[::b]%s[::-]\n\nkey number on the card: %d\ntype: %s\nkey domain: ", tview.Escape(orStr(k.Label, "(no label)")), k.ID, orStr(k.Algo, "unknown"))
	if k.Domain >= 0 {
		s += fmt.Sprint(k.Domain)
	} else {
		s += "unknown"
	}
	if len(k.Algorithms) > 0 {
		s += "\nmay be used for: " + strings.Join(k.Algorithms, ", ")
	}
	if k.Uses >= 0 {
		s += fmt.Sprintf("\nuse counter: %d", k.Uses)
	}
	if len(k.CKAID) > 0 {
		id := hex.EncodeToString(k.CKAID)
		s += "\n\nCKA_ID (what hsmgate calls the key of a card in its configuration):\n[::b]" + id + "[::-]"
		if t, l := a.configuredKey(id); t != "" {
			s += fmt.Sprintf("\n\nIn the configuration: token [::b]%s[::-], label [::b]%s[::-].", tview.Escape(t), tview.Escape(l))
		} else if a.cfgLoose() != nil {
			s += "\n\nNot in the configuration: no token names this id."
		}
	}
	return s
}

// configuredKey says whether a token of the configuration has this CKA_ID, and under which label.
func (a *App) configuredKey(id string) (token, label string) {
	cfg := a.cfgLoose()
	if cfg == nil {
		return "", ""
	}
	for _, tk := range cfg.Tokens {
		if tk.Type != "pkcs11" {
			continue
		}
		for l, v := range tk.Keys {
			if strings.EqualFold(v, id) {
				return tk.Name, l
			}
		}
	}
	return "", ""
}

// cardRead reads the card in the background and then redraws the page. When the service is running and holds a card open, it asks first: a second program that selects the
// application of the card may end the login of the service (not tested).
func (a *App) cardRead(redraw func()) {
	if a.card.busy {
		return
	}
	if a.serviceHoldsCard() {
		a.ask("The service holds a card", "hsmgate is running and its card is open. Reading the card with a second program selects the application of the card again, which may end the login of the service's own connection. When it was tried (2026-11-18, one service and one card) the service went on sealing and opening texts afterwards, but that is one try.\n\nRead the card anyway?", []string{"Read", "Cancel"}, func(i int) {
			if i == 0 {
				a.cardReadNow(redraw)
			}
		})
		return
	}
	a.cardReadNow(redraw)
}

func (a *App) serviceHoldsCard() bool {
	sock := a.socket()
	if sock == "" {
		return false
	}
	cfg := a.cfgLoose()
	if cfg == nil {
		return false
	}
	st, err := sys.Status(sock)
	if err != nil {
		return false
	}
	for _, tk := range cfg.Tokens {
		if tk.Type == "pkcs11" && st[tk.Name] == "ready" {
			return true
		}
	}
	return false
}

func (a *App) cardReadNow(redraw func()) {
	a.card.busy, a.card.err = true, ""
	redraw()
	reader := a.card.reader
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tree, err := a.readCard(ctx, reader)
		a.app.QueueUpdateDraw(func() {
			a.card.busy = false
			var pick needReader
			if errors.As(err, &pick) {
				a.card.err = ""
				redraw()
				a.readerMenu(pick.readers, func() { a.cardRead(redraw) })
				return
			}
			if err != nil {
				a.card.err, a.card.tree = err.Error(), nil
			} else {
				a.card.tree = tree
			}
			if a.section == "card" {
				redraw()
			}
		})
	}()
}

// needReader is what readCard returns when more than one reader has a card and none was chosen: reading the first would be a guess about which card is meant.
type needReader struct{ readers []card.Reader }

func (needReader) Error() string { return "more than one reader has a card: choose one" }

// readCard finds the reader (the chosen one, or the only one that has a card) and reads it.
func (a *App) readCard(ctx context.Context, reader int) (*card.Tree, error) {
	rs, err := card.Readers(ctx, a.cardRun())
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("PC/SC shows no card reader.\n\nIs pcscd running (systemctl status pcscd)? From an SSH session pcscd may refuse a program that is not on the console: run this on the console, or as the user that pcscd allows (polkit)")
	}
	if reader < 0 {
		var with []card.Reader
		for _, r := range rs {
			if r.HasCard {
				with = append(with, r)
			}
		}
		switch len(with) {
		case 0:
			return nil, fmt.Errorf("none of the %d reader(s) has a card in it", len(rs))
		case 1:
			return card.Read(ctx, a.cardRun(), with[0])
		}
		return nil, needReader{rs}
	}
	for _, r := range rs {
		if r.Nr == reader {
			if !r.HasCard {
				return nil, fmt.Errorf("there is no card in the reader %d (%s)", r.Nr, r.Name)
			}
			return card.Read(ctx, a.cardRun(), r)
		}
	}
	return nil, fmt.Errorf("the reader %d is not there any more (PC/SC lists %d)", reader, len(rs))
}

// cardChooseReader lists the readers (the Reader button) and reads the one that is chosen.
func (a *App) cardChooseReader(read func()) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rs, err := card.Readers(ctx, a.cardRun())
	if err != nil {
		a.fail(err)
		return
	}
	if len(rs) == 0 {
		a.fail(fmt.Errorf("PC/SC shows no card reader.\n\nIs pcscd running (systemctl status pcscd)?"))
		return
	}
	a.readerMenu(rs, read)
}

// readerMenu is the menu of the readers: the first line lets the page choose (the only reader that has a card), the others are the readers as PC/SC numbers them; the one in use
// is marked. Choosing one reads its card.
func (a *App) readerMenu(rs []card.Reader, read func()) {
	l := tview.NewList().ShowSecondaryText(false)
	l.SetBorder(true).SetTitle(" Choose the reader (Enter: read its card, Esc: cancel) ")
	l.SetSelectedBackgroundColor(tcell.ColorNavy).SetSelectedTextColor(tcell.ColorWhite)
	mark := func(on bool) string {
		if on {
			return "* "
		}
		return "  "
	}
	closeMenu := func() { a.pages.RemovePage("form"); a.app.SetFocus(a.content) } // back to the page, not to the menu on the left
	choose := func(nr int) func() {
		return func() {
			closeMenu()
			a.card.reader = nr
			read()
		}
	}
	l.AddItem(mark(a.card.reader < 0)+"automatic: the only reader that has a card", "", 0, choose(-1))
	current := 0
	for i, r := range rs {
		state := "no card"
		if r.HasCard {
			state = "card   "
		}
		l.AddItem(fmt.Sprintf("%s%d  %s  %s", mark(a.card.reader == r.Nr), r.Nr, state, r.Name), "", 0, choose(r.Nr))
		if a.card.reader == r.Nr {
			current = i + 1
		}
	}
	l.SetCurrentItem(current)
	l.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			closeMenu()
			return nil
		}
		return ev
	})
	a.modalPage("form", l, 100, len(rs)+5)
}

// cfgLoose is the configuration as it is written, read without the checks of the service (which refuse a file that this user does not own, for one): the page needs only the tokens.
func (a *App) cfgLoose() *config.Config {
	raw, err := a.doc.Bytes()
	if err != nil {
		return nil
	}
	c, err := config.Parse(raw)
	if err != nil {
		return nil
	}
	return c
}
