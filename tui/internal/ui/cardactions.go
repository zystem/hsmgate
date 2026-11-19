package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/zystem/hsmgate/tui/internal/card"
)

// The actions of the Card page change the card, or make a file for it. Each is a form (with the User PIN where the card wants it), and for what cannot be undone a word to type. The
// PIN is typed masked, goes down a pipe to opensc-explorer (not into a command line) and is overwritten after use. Before a PIN is sent the page asks the card how many tries are
// left and refuses to send one when only one is left: a wrong PIN there would block the card.

type cardAction struct {
	label string
	run   func()
}

// cardOpen opens a connection to the card of the tree (a test gives its own).
func (a *App) cardOpen(ctx context.Context, r card.Reader) (card.Conn, error) {
	if a.opt.CardOpen != nil {
		return a.opt.CardOpen(ctx, r)
	}
	return card.OpenExplorer(ctx, nil, r)
}

// cardActions lists what can be done with a line of the tree.
func (a *App) cardActions(ref any) []cardAction {
	var acts []cardAction
	add := func(label string, f func()) { acts = append(acts, cardAction{label, f}) }
	switch v := ref.(type) {
	case *card.Tree:
		add("Make a DKEK share file…", a.actMakeShare)
		add("Import a key from a file (unwrap)…", func() { a.actImportKey(-1) })
		add("Export the device ID of this card (for an XKEK group)…", a.actExportDeviceID)
	case card.PIN:
		if v.Name == "User PIN" {
			add("Change the User PIN…", a.actChangePIN)
			add("Unblock the User PIN with the SO PIN…", a.actUnblockPIN)
		} else {
			add("Change the SO PIN…", a.actChangeSOPIN)
		}
	case card.Domain:
		switch {
		case !v.Created:
			add("Create a DKEK key domain…", func() { a.actCreateDomain(v.Number) })
			add("Create an XKEK key domain from a membership file…", func() { a.actCreateXKEK(v.Number) })
		case v.XKEK:
			add("Generate a key (EC or RSA)…", func() { a.actGenerateKey(v.Number) })
			add("Delete the key domain…", func() { a.actDeleteDomain(v) })
		default:
			if v.Outstanding == 0 {
				add("Generate a key (EC or RSA)…", func() { a.actGenerateKey(v.Number) })
			}
			if v.Outstanding > 0 {
				add("Import a DKEK share from a file…", func() { a.actImportShare(v) })
			} else {
				add("Import a key from a file (unwrap)…", func() { a.actImportKey(v.Number) })
			}
			add("Delete the key encryption key (DKEK)…", func() { a.actDeleteKEK(v) })
			add("Delete the key domain…", func() { a.actDeleteDomain(v) })
		}
	case card.Key:
		if hasAlg(v, "ECDSA SHA-256") {
			add("Sign a key domain membership (group signer)…", func() { a.actSignMembership(v) })
		}
		if hasWrap(v) {
			add("Export the key to a file (wrap)…", func() { a.actExportKey(v) })
		}
		add("Delete the key…", func() { a.actDeleteKey(v) })
	}
	return acts
}

func hasWrap(k card.Key) bool { return hasAlg(k, "wrap") }

func hasAlg(k card.Key, name string) bool {
	for _, a := range k.Algorithms {
		if a == name {
			return true
		}
	}
	return false
}

// cardMenu shows the actions of a line as a menu.
func (a *App) cardMenu(ref any) {
	acts := a.cardActions(ref)
	if len(acts) == 0 {
		a.notice("Actions", "There is nothing to do with this line.")
		return
	}
	l := tview.NewList().ShowSecondaryText(false)
	l.SetBorder(true).SetTitle(" Actions (Enter: choose, Esc: cancel) ")
	l.SetSelectedBackgroundColor(tcell.ColorNavy).SetSelectedTextColor(tcell.ColorWhite)
	for _, act := range acts {
		act := act
		l.AddItem(act.label, "", 0, func() { a.cardClose(); act.run() })
	}
	l.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			a.cardClose()
			return nil
		}
		return ev
	})
	a.modalPage("form", l, 70, len(acts)+4)
}

// cardClose closes a dialog of the page and gives the focus back to the page, not to the menu on the left.
func (a *App) cardClose() { a.pages.RemovePage("form"); a.app.SetFocus(a.content) }

// ---- the forms -----------------------------------------------------------------------------------------------------------------------------------------

func fieldText(f *tview.Form, label string) string {
	if it, ok := f.GetFormItemByLabel(label).(*tview.InputField); ok {
		return it.GetText()
	}
	return ""
}

func (a *App) pinHint() string {
	t := a.card.tree
	if t == nil {
		return ""
	}
	return fmt.Sprintf("The User PIN has %d tries left (as read). A wrong PIN uses one; the page does not send a PIN when one try is left.", max(t.UserPIN.Tries, 0))
}

// cardForm shows a form with a text above its fields; nfields says how many fields it has, and the dialog is as high as the text and the fields need (on a small screen the text
// scrolls).
func (a *App) cardForm(title, text string, nfields int, fields func(f *tview.Form), button string, submit func(f *tview.Form)) {
	width := 84
	rows := strings.Count(text, "\n") + 1
	for _, l := range strings.Split(text, "\n") {
		rows += len(l) / (width - 8)
	}
	f := tview.NewForm()
	f.AddTextView("", text, 0, rows, true, false)
	fields(f)
	f.AddButton(button, func() { submit(f) })
	f.AddButton("Cancel", a.cardClose)
	a.form(title, f, width, rows+nfields+5)
	f.SetCancelFunc(a.cardClose)
	a.cardFormCur = f
}

// ---- the actions ---------------------------------------------------------------------------------------------------------------------------------------

func (a *App) actChangePIN() {
	a.cardForm("Change the User PIN", "Give the current User PIN and the new one: it must have as many characters as the current one (the card refuses another length). The card checks the current one: a wrong one uses a try.\n"+a.pinHint(), 3, func(f *tview.Form) {
		f.AddPasswordField("Current PIN", "", 20, '*', nil)
		f.AddPasswordField("New PIN", "", 20, '*', nil)
		f.AddPasswordField("New PIN again", "", 20, '*', nil)
	}, "Change", func(f *tview.Form) {
		cur, next, again := fieldText(f, "Current PIN"), fieldText(f, "New PIN"), fieldText(f, "New PIN again")
		if err := checkNewPIN(next, again); err != nil {
			a.fail(err)
			return
		}
		if len(cur) != len(next) {
			a.fail(fmt.Errorf("the new User PIN must have the same number of characters as the current one (%d): the card refuses another length", len(cur)))
			return
		}
		a.cardClose()
		a.cardWork("Change the User PIN", nil, func(s *card.Session) (string, error) {
			if err := a.pinTriesOK(s, "User PIN", 0x81); err != nil {
				return "", err
			}
			if err := s.ChangeUserPIN([]byte(cur), []byte(next)); err != nil {
				return "", err
			}
			return "The User PIN is changed.", nil
		})
	})
}

func checkNewPIN(next, again string) error {
	switch {
	case next != again:
		return errors.New("the two new PINs are not the same: nothing was done")
	case len(next) < 6 || len(next) > 16:
		return errors.New("a PIN is 6 to 16 characters: nothing was done")
	}
	return nil
}

func (a *App) actChangeSOPIN() {
	a.cardForm("Change the SO PIN", "Give the current SO PIN (the initialization code) and the new one (8 characters, or 16 hexadecimal digits as the vendor's tools write it). Keep it apart from the User PIN.", 3, func(f *tview.Form) {
		f.AddPasswordField("Current SO PIN", "", 20, '*', nil)
		f.AddPasswordField("New SO PIN", "", 20, '*', nil)
		f.AddPasswordField("New SO PIN again", "", 20, '*', nil)
	}, "Change", func(f *tview.Form) {
		cur, next, again := fieldText(f, "Current SO PIN"), fieldText(f, "New SO PIN"), fieldText(f, "New SO PIN again")
		if _, err := card.SOPINBytes(next); err != nil || next != again {
			a.fail(errors.New("the two new SO PINs must be the same, 8 characters or 16 hexadecimal digits: nothing was done"))
			return
		}
		a.cardClose()
		a.cardWork("Change the SO PIN", nil, func(s *card.Session) (string, error) {
			if err := a.pinTriesOK(s, "SO PIN", 0x88); err != nil {
				return "", err
			}
			if err := s.ChangeSOPIN([]byte(cur), []byte(next)); err != nil {
				return "", err
			}
			return "The SO PIN is changed.", nil
		})
	})
}

func (a *App) actUnblockPIN() {
	a.cardForm("Unblock the User PIN", "Give the SO PIN and a new User PIN (6 to 16 characters). The User PIN is set to the new one and its tries are given back.", 3, func(f *tview.Form) {
		f.AddPasswordField("SO PIN", "", 20, '*', nil)
		f.AddPasswordField("New User PIN", "", 20, '*', nil)
		f.AddPasswordField("New User PIN again", "", 20, '*', nil)
	}, "Unblock", func(f *tview.Form) {
		so, next, again := fieldText(f, "SO PIN"), fieldText(f, "New User PIN"), fieldText(f, "New User PIN again")
		if err := checkNewPIN(next, again); err != nil {
			a.fail(err)
			return
		}
		a.cardClose()
		a.cardWork("Unblock the User PIN", nil, func(s *card.Session) (string, error) {
			if err := a.pinTriesOK(s, "SO PIN", 0x88); err != nil {
				return "", err
			}
			if err := s.UnblockUserPIN([]byte(so), []byte(next)); err != nil {
				return "", err
			}
			return "The User PIN is set to the new one and has all its tries.", nil
		})
	})
}

func (a *App) actCreateDomain(n int) {
	a.cardForm(fmt.Sprintf("Create the key domain %d", n), "A key domain holds keys that share one key encryption key (DKEK). The DKEK is made of shares that are imported one by one: say how many (1 for a card of one holder, more when several people each keep a share).\n"+a.pinHint(), 3, func(f *tview.Form) {
		f.AddInputField("Number of shares", "1", 4, nil, nil)
		f.AddInputField("Label", "", 30, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Create", func(f *tview.Form) {
		shares64, err := strconv.ParseUint(strings.TrimSpace(fieldText(f, "Number of shares")), 10, 8) // 0 to 255 by the size
		label := strings.TrimSpace(fieldText(f, "Label"))
		if err != nil || shares64 < 1 {
			a.fail(errors.New("the number of shares is 1 to 255: nothing was done"))
			return
		}
		if len(label) > 60 {
			a.fail(errors.New("a label of more than 60 characters: nothing was done"))
			return
		}
		shares := byte(shares64) // #nosec G115 -- parsed with a limit of 8 bits
		pin := []byte(fieldText(f, "User PIN"))
		a.cardClose()
		a.cardWork("Create the key domain", pin, func(s *card.Session) (string, error) {
			d, err := s.CreateDKEKDomain(byte(n), shares, label) // #nosec G115 -- a key domain number
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("The key domain %d is made: %d share(s) to import. Make a share file (on the card line, Enter) and import it into this domain.", n, d.Shares), nil
		})
	})
}

// the formats of a share file as the form offers them (the first is the default)
var shareFormats = []struct {
	label  string
	format card.ShareFormat
}{
	{"strong: AES-256-GCM, PBKDF2-SHA-256 (only this program reads it)", card.Strong},
	{"compatible: Smart Card Shell and sc-hsm-tool read it (MD5 key derivation, weak for a password)", card.Compatible},
}

func (a *App) actMakeShare() {
	a.cardForm("Make a DKEK share file", "A share is 32 random bytes in a file that a password protects. Keep the file and its password in different places: with all the shares of a DKEK both are needed to make it again on another card.\nThe default format is the strong one; choose the compatible one only when another tool (the vendor's card manager) has to read the file: its protection is the slow key derivation, not the hash. The page opens both. Making a file takes a few seconds. Nothing is sent to the card.", 4, func(f *tview.Form) {
		f.AddInputField("File", "dkek-share-1.pbe", 50, nil, nil)
		labels := make([]string, len(shareFormats))
		for i, sf := range shareFormats {
			labels[i] = sf.label
		}
		f.AddDropDown("Format", labels, 0, nil)
		f.AddPasswordField("Password", "", 30, '*', nil)
		f.AddPasswordField("Password again", "", 30, '*', nil)
	}, "Make", func(f *tview.Form) {
		idx := 0
		if dd, ok := f.GetFormItemByLabel("Format").(*tview.DropDown); ok {
			idx, _ = dd.GetCurrentOption()
		}
		a.makeShare(strings.TrimSpace(fieldText(f, "File")), fieldText(f, "Password"), fieldText(f, "Password again"), shareFormats[idx].format)
	})
}

// makeShare checks the answers of the form and makes the file.
func (a *App) makeShare(path, pw, again string, format card.ShareFormat) {
	switch {
	case path == "":
		a.fail(errors.New("no file name: nothing was done"))
		return
	case pw != again || len(pw) < 8:
		a.fail(errors.New("the password must be the same twice and at least 8 characters: nothing was done"))
		return
	}
	if _, err := os.Stat(path); err == nil {
		a.fail(fmt.Errorf("%s is there already: choose another name (nothing is overwritten)", path))
		return
	}
	a.cardClose()
	a.working("Making the share (a few seconds)…", func() (string, error) {
		share, err := card.NewShare(nil)
		if err != nil {
			return "", err
		}
		defer card.Wipe(share)
		file, err := card.EncryptShare(format, share, []byte(pw), nil)
		if err != nil {
			return "", err
		}
		if err := writeNew(path, file); err != nil {
			return "", err
		}
		note := ""
		if format == card.Compatible {
			note = "\nThe file is in the compatible format: its password is protected only by the slow key derivation, so keep the file as secret as the password."
		}
		return fmt.Sprintf("The share is written to %s (the %s format, mode 0600).\nThe key check value of this share: %X\nFor a key domain of one share the card will show this value after the import.%s", path, format, card.KCV(share), note), nil
	})
}

func (a *App) actImportShare(d card.Domain) {
	a.cardForm(fmt.Sprintf("Import a share into the key domain %d", d.Number), fmt.Sprintf("%d of %d shares are still to import. Give the file of a share and its password.\nOpening the file takes a few seconds.\n%s", d.Outstanding, d.Shares, a.pinHint()), 3, func(f *tview.Form) {
		f.AddInputField("File", "", 50, nil, nil)
		f.AddPasswordField("Password of the file", "", 30, '*', nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Import", func(f *tview.Form) {
		path, pw, pin := strings.TrimSpace(fieldText(f, "File")), fieldText(f, "Password of the file"), []byte(fieldText(f, "User PIN"))
		raw, err := readSmall(path, 128)
		if err != nil {
			a.fail(err)
			return
		}
		a.cardClose()
		a.cardWork("Import the share", pin, func(s *card.Session) (string, error) {
			share, err := card.DecryptShare(raw, []byte(pw))
			if err != nil {
				return "", err
			}
			defer card.Wipe(share)
			got, err := s.ImportShare(byte(d.Number), share) // #nosec G115 -- a key domain number
			if err != nil {
				return "", err
			}
			if got.Outstanding > 0 {
				return fmt.Sprintf("The share is in. %d share(s) are still to import. The key check value so far: %s.", got.Outstanding, got.KCV), nil
			}
			return fmt.Sprintf("The last share is in: the DKEK of the key domain %d is complete.\nKey check value: %s", d.Number, got.KCV), nil
		})
	})
}

func (a *App) actDeleteKEK(d card.Domain) {
	a.cardDestroy(fmt.Sprintf("Delete the DKEK of the key domain %d", d.Number),
		fmt.Sprintf("This deletes the key encryption key of the key domain %d. The keys in it stay on the card but can no longer be wrapped or unwrapped, and a copy of them that was wrapped under this DKEK can be opened only on a card that gets the same shares again.", d.Number), "delete",
		func(s *card.Session) (string, error) {
			if err := s.DeleteKEK(byte(d.Number)); err != nil { // #nosec G115 -- a key domain number
				return "", err
			}
			return fmt.Sprintf("The DKEK of the key domain %d is deleted.", d.Number), nil
		})
}

func (a *App) actDeleteDomain(d card.Domain) {
	a.cardDestroy(fmt.Sprintf("Delete the key domain %d", d.Number),
		fmt.Sprintf("This deletes the key domain %d with its DKEK and its label. The card refuses while a key is still in it: delete the keys first (back them up before, with Export).", d.Number), "delete",
		func(s *card.Session) (string, error) {
			if err := s.DeleteDomain(byte(d.Number)); err != nil { // #nosec G115 -- a key domain number
				return "", err
			}
			return fmt.Sprintf("The key domain %d is deleted.", d.Number), nil
		})
}

func (a *App) actDeleteKey(k card.Key) {
	label := orStr(k.Label, fmt.Sprintf("key %d", k.ID))
	a.cardDestroy(fmt.Sprintf("Delete the key %d (%s)", k.ID, label),
		fmt.Sprintf("This deletes the private key %d (%s, %s) from the card. **It cannot be undone**: unless a wrapped copy exists (Export) what was sealed under this key cannot be opened again. A service that uses the key stops working.", k.ID, label, orStr(k.Algo, "?")), "delete",
		func(s *card.Session) (string, error) {
			if err := s.DeleteKey(byte(k.ID)); err != nil { // #nosec G115 -- a key number
				return "", err
			}
			return fmt.Sprintf("The key %d (%s) is deleted.", k.ID, label), nil
		})
}

// cardDestroy is the form of what cannot be undone: the text, the User PIN and the word to type.
func (a *App) cardDestroy(title, text, word string, work func(s *card.Session) (string, error)) {
	a.cardForm(title, strings.ReplaceAll(text, "**", "")+"\n"+a.pinHint(), 2, func(f *tview.Form) {
		f.AddInputField("Type "+word+":", "", 12, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Do it", func(f *tview.Form) {
		if strings.TrimSpace(fieldText(f, "Type "+word+":")) != word {
			a.fail(fmt.Errorf("you did not type %q: nothing was done", word))
			return
		}
		pin := []byte(fieldText(f, "User PIN"))
		a.cardClose()
		a.cardWork(title, pin, work)
	})
}

func (a *App) actExportKey(k card.Key) {
	label := orStr(k.Label, fmt.Sprintf("key%d", k.ID))
	a.cardForm(fmt.Sprintf("Export the key %d (%s)", k.ID, label), "The key leaves the card only wrapped (encrypted) under the DKEK of its key domain, in a file the vendor's card manager reads (.wky). It can be unwrapped only on a card that has the same DKEK. Keep the file with the shares, not with the card.\n"+a.pinHint(), 2, func(f *tview.Form) {
		f.AddInputField("File", safeName(label)+".wky", 50, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Export", func(f *tview.Form) {
		path, pin := strings.TrimSpace(fieldText(f, "File")), []byte(fieldText(f, "User PIN"))
		if _, err := os.Stat(path); err == nil {
			a.fail(fmt.Errorf("%s is there already: choose another name (nothing is overwritten)", path))
			return
		}
		a.cardClose()
		a.cardWork("Export the key", pin, func(s *card.Session) (string, error) {
			kf, err := s.ExportKey(byte(k.ID)) // #nosec G115 -- a key number
			if err != nil {
				return "", err
			}
			if err := writeNew(path, kf.Encode()); err != nil {
				return "", err
			}
			return fmt.Sprintf("The key %d (%s) is written to %s (mode 0600): %d bytes wrapped, %d certificate(s).", k.ID, label, path, len(kf.Blob), len(kf.Certs)), nil
		})
	})
}

// actImportKey unwraps a key from a file. The card finds the key domain by the check value that the file names; domain is only for the text.
func (a *App) actImportKey(domain int) {
	where := "the key domain whose DKEK wrapped it"
	if domain >= 0 {
		where = fmt.Sprintf("the key domain %d (when its DKEK wrapped it)", domain)
	}
	a.cardForm("Import a key from a file (unwrap)", "The file is a wrapped key (.wky of the vendor's card manager, or the blob alone). The card puts it into "+where+" under the lowest free key number, and the page writes its label and certificates. The key domain must have its complete DKEK.\n"+a.pinHint(), 2, func(f *tview.Form) {
		f.AddInputField("File", "", 50, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Import", func(f *tview.Form) {
		path, pin := strings.TrimSpace(fieldText(f, "File")), []byte(fieldText(f, "User PIN"))
		raw, err := readSmall(path, 1<<20)
		if err != nil {
			a.fail(err)
			return
		}
		kf, err := card.ParseKeyFile(raw)
		if err != nil {
			a.fail(err)
			return
		}
		if l := kf.Label(); l != "" && a.labelOnCard(l) {
			a.fail(fmt.Errorf("a key with the label %q is on the card already: nothing was done (delete it, or change the label in the file's description)", l))
			return
		}
		a.cardClose()
		a.cardWork("Import the key", pin, func(s *card.Session) (string, error) {
			id, err := s.ImportKey(kf)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("The key is on the card as the key %d (%s, %s).", id, orStr(kf.Label(), "no label"), orStr(kf.Algo(), "type not told")), nil
		})
	})
}

func (a *App) labelOnCard(label string) bool {
	t := a.card.tree
	if t == nil {
		return false
	}
	for _, d := range t.Domains {
		for _, k := range d.Keys {
			if k.Label == label {
				return true
			}
		}
	}
	for _, k := range t.Loose {
		if k.Label == label {
			return true
		}
	}
	return false
}

// ---- the work ------------------------------------------------------------------------------------------------------------------------------------------

// pinTriesOK looks at a PIN before a command that costs a try when the PIN is wrong: it refuses when the PIN is blocked or has one try left.
func (a *App) pinTriesOK(s *card.Session, name string, ref byte) error {
	st, err := s.PINState(name, ref)
	if err != nil {
		return err
	}
	switch {
	case st.Blocked:
		return fmt.Errorf("the %s is blocked: no try is left", name)
	case !st.Verified && st.Tries >= 0 && st.Tries < 2:
		return fmt.Errorf("only %d try of the %s is left: the page does not send a PIN that may be wrong (a wrong one blocks it). Check the PIN another way first", st.Tries, name)
	}
	return nil
}

// cardWork runs a command session on the card: opens it, selects the application, gives the User PIN when one is passed, runs work, and shows what came of it. The tree is read again
// after it. The PIN is overwritten when it is done.
func (a *App) cardWork(title string, userPIN []byte, work func(s *card.Session) (string, error)) {
	t := a.card.tree
	if t == nil {
		a.notice(title, "Read the card first (the Read the card button).")
		return
	}
	run := func() {
		a.working(title+"…", func() (string, error) {
			defer card.Wipe(userPIN)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			conn, err := a.cardOpen(ctx, t.Reader)
			if err != nil {
				return "", err
			}
			s := card.NewSession(conn)
			defer s.Close()
			if err := s.Select(); err != nil {
				return "", err
			}
			if userPIN != nil {
				if err := a.pinTriesOK(s, "User PIN", 0x81); err != nil {
					return "", err
				}
				p, err := s.VerifyUserPIN(userPIN)
				if err != nil {
					return "", err
				}
				if !p.Verified {
					return "", fmt.Errorf("the card did not take the User PIN: %s", p.Text())
				}
			}
			return work(s)
		})
	}
	if a.serviceHoldsCard() && !a.card.writeOK {
		a.ask("The service holds a card", "hsmgate is running and its card is open. This changes the card and selects its application again, which may end the login of the service's own connection. When it was tried (2026-11-18, one service and one card) the service went on sealing and opening texts, but that is one try.\n\nGo on?", []string{"Go on", "Cancel"}, func(i int) {
			if i == 0 {
				a.card.writeOK = true
				run()
			}
		})
		return
	}
	run()
}

// working shows that something is being done, runs it off the screen's goroutine, then shows the result and reads the card again.
func (a *App) working(text string, f func() (string, error)) {
	tv := tview.NewTextView().SetText("\n  " + text)
	tv.SetBorder(true)
	a.modalPage("working", tv, 60, 5)
	go func() {
		msg, err := f()
		a.app.QueueUpdateDraw(func() {
			a.pages.RemovePage("working")
			a.app.SetFocus(a.content)
			if err != nil {
				a.fail(err)
			} else {
				a.notice("Done", msg)
			}
			if a.card.tree != nil && a.card.redraw != nil && a.section == "card" {
				a.cardReadNow(a.card.redraw)
			}
		})
	}()
}

// ---- files ---------------------------------------------------------------------------------------------------------------------------------------------

// writeNew writes a file that is not there yet, with mode 0600.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a path the operator typed
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// readSmall reads a file that must not be larger than max bytes.
func readSmall(path string, max int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max || st.Size() == 0 {
		return nil, fmt.Errorf("%s is not a file of the size expected (at most %d bytes)", path, max)
	}
	return os.ReadFile(filepath.Clean(path)) // #nosec G304 -- a path the operator typed
}

// safeName makes a file name of a label.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "key"
	}
	return b.String()
}

// ---- keys and XKEK -------------------------------------------------------------------------------------------------------------------------------------

// the kinds of key the form offers, and what a key of each may be used for
var keyKinds = []struct {
	label string
	kind  string
	bits  int
}{
	{"EC P-256", "EC", 256},
	{"RSA 2048 (takes the card about 20 seconds)", "RSA", 2048},
	{"RSA 3072 (takes the card about a minute)", "RSA", 3072},
	{"RSA 4096 (takes the card a minute or more)", "RSA", 4096},
}

var keyUses = []struct {
	label string
	kind  string
	names []string
}{
	{"sign (ECDSA)", "EC", []string{"sign"}},
	{"sign (ECDSA) and wrap (backup)", "EC", []string{"sign", "wrap"}},
	{"key agreement (ECDH) and wrap: what hsmgate uses", "EC", []string{"derive", "wrap"}},
	{"sign, key agreement and wrap", "EC", []string{"sign", "derive", "wrap"}},
	{"sign (RSA)", "RSA", []string{"sign"}},
	{"decrypt (RSA)", "RSA", []string{"decrypt"}},
	{"sign, decrypt and wrap", "RSA", []string{"sign", "decrypt", "wrap"}},
}

func dropIndex(f *tview.Form, label string) int {
	if dd, ok := f.GetFormItemByLabel(label).(*tview.DropDown); ok {
		i, _ := dd.GetCurrentOption()
		return i
	}
	return 0
}

func (a *App) actGenerateKey(domain int) {
	a.cardForm(fmt.Sprintf("Generate a key in the key domain %d", domain), "The card makes the key and the private key never leaves it (only wrapped under the DKEK, if you allow wrap). Give it a label and say what it may be used for: a key of hsmgate is an EC key for key agreement. An RSA key takes the card a long time; the page waits.\n"+a.pinHint(), 4, func(f *tview.Form) {
		f.AddInputField("Label", "", 30, nil, nil)
		kinds := make([]string, len(keyKinds))
		for i, k := range keyKinds {
			kinds[i] = k.label
		}
		f.AddDropDown("Type", kinds, 0, nil)
		uses := make([]string, len(keyUses))
		for i, u := range keyUses {
			uses[i] = u.kind + ": " + u.label
		}
		f.AddDropDown("Use", uses, 2, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Generate", func(f *tview.Form) {
		kind, use := keyKinds[dropIndex(f, "Type")], keyUses[dropIndex(f, "Use")]
		label := strings.TrimSpace(fieldText(f, "Label"))
		switch {
		case label == "" || len(label) > 60:
			a.fail(errors.New("a label of 1 to 60 characters is needed: nothing was done"))
			return
		case use.kind != kind.kind:
			a.fail(fmt.Errorf("the use %q is for %s keys and the type is %s: nothing was done", use.label, use.kind, kind.kind))
			return
		case a.labelOnCard(label):
			a.fail(fmt.Errorf("a key with the label %q is on the card already: nothing was done", label))
			return
		}
		pin := []byte(fieldText(f, "User PIN"))
		a.cardClose()
		spec := card.GenSpec{Kind: kind.kind, Bits: kind.bits, Label: label, Algorithms: card.AlgorithmByName(kind.kind, use.names...), Domain: domain}
		a.cardWork("Generate the key", pin, func(s *card.Session) (string, error) {
			id, _, keyID, err := s.GenerateKey(spec)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("The key %d (%s, %s) is made in the key domain %d.\nCKA_ID (what hsmgate calls the key of a card): %X", id, label, kind.kind+"-"+fmt.Sprint(kind.bits), domain, keyID), nil
		})
	})
}

func (a *App) actExportDeviceID() {
	a.cardForm("Export the device ID of this card", "The device ID says which card a key domain membership is for: it holds the certificates of the card, which are not secret. Give the file to the person who holds the group signer key of the XKEK group.\nNo PIN is needed.", 1, func(f *tview.Form) {
		f.AddInputField("File", "device-id.id", 50, nil, nil)
	}, "Export", func(f *tview.Form) {
		path := strings.TrimSpace(fieldText(f, "File"))
		if _, err := os.Stat(path); err == nil {
			a.fail(fmt.Errorf("%s is there already: choose another name (nothing is overwritten)", path))
			return
		}
		a.cardClose()
		a.cardWork("Export the device ID", nil, func(s *card.Session) (string, error) {
			certs, err := s.DeviceCertificates()
			if err != nil {
				return "", err
			}
			if err := writeNew(path, card.EncodeDeviceID(certs)); err != nil {
				return "", err
			}
			return fmt.Sprintf("The device ID is written to %s (%d bytes).", path, len(card.EncodeDeviceID(certs))), nil
		})
	})
}

func (a *App) actSignMembership(k card.Key) {
	a.cardForm(fmt.Sprintf("Sign a membership with the key %d (%s)", k.ID, orStr(k.Label, "no label")), "The key is the group signer of an XKEK group. Give the device ID file of the card that is to belong to the group (it can be this card); the page signs the membership and writes the membership file, which that card then uses to make its XKEK key domain. The identifier of the key domain is the public key of this key.\n"+a.pinHint(), 3, func(f *tview.Form) {
		f.AddInputField("Device ID file", "", 50, nil, nil)
		f.AddInputField("Membership file", "membership.kdm", 50, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Sign", func(f *tview.Form) {
		in, out, pin := strings.TrimSpace(fieldText(f, "Device ID file")), strings.TrimSpace(fieldText(f, "Membership file")), []byte(fieldText(f, "User PIN"))
		raw, err := readSmall(in, 4096)
		if err != nil {
			a.fail(err)
			return
		}
		dev, err := card.ParseDeviceID(raw)
		if err != nil {
			a.fail(err)
			return
		}
		if _, err := os.Stat(out); err == nil {
			a.fail(fmt.Errorf("%s is there already: choose another name (nothing is overwritten)", out))
			return
		}
		a.cardClose()
		a.cardWork("Sign the membership", pin, func(s *card.Session) (string, error) {
			mf, err := s.SignMembership(byte(k.ID), dev) // #nosec G115 -- a key number
			if err != nil {
				return "", err
			}
			if err := writeNew(out, mf.Encode()); err != nil {
				return "", err
			}
			return fmt.Sprintf("The membership is written to %s (%d bytes).\nThe key domain it is for: %X", out, len(mf.Encode()), mf.DomainUID()), nil
		})
	})
}

func (a *App) actCreateXKEK(n int) {
	a.cardForm(fmt.Sprintf("Create the XKEK key domain %d", n), "An XKEK key domain belongs to a group of cards. Give the membership file that the holder of the group signer key made for this card. The card checks the certificates in it and makes the domain.\n"+a.pinHint(), 3, func(f *tview.Form) {
		f.AddInputField("Membership file", "", 50, nil, nil)
		f.AddInputField("Label", "", 30, nil, nil)
		f.AddPasswordField("User PIN", "", 20, '*', nil)
	}, "Create", func(f *tview.Form) {
		path, label, pin := strings.TrimSpace(fieldText(f, "Membership file")), strings.TrimSpace(fieldText(f, "Label")), []byte(fieldText(f, "User PIN"))
		raw, err := readSmall(path, 16384)
		if err != nil {
			a.fail(err)
			return
		}
		mf, err := card.ParseMembershipFile(raw)
		if err != nil {
			a.fail(err)
			return
		}
		if len(label) > 60 {
			a.fail(errors.New("a label of more than 60 characters: nothing was done"))
			return
		}
		a.cardClose()
		a.cardWork("Create the XKEK key domain", pin, func(s *card.Session) (string, error) {
			d, err := s.CreateXKEKDomain(byte(n), mf.GroupRequest, mf.Membership, mf.Signer, label) // #nosec G115 -- a key domain number
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("The XKEK key domain %d is made. Key domain: %s.", n, d.DomainID), nil
		})
	})
}
