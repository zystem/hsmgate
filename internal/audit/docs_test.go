package audit

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// Every field of a line is described in docs/audit-log.md.
func TestEveryFieldIsDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../docs/audit-log.md")
	if err != nil {
		t.Fatal(err)
	}
	ty := reflect.TypeOf(Event{})
	for i := 0; i < ty.NumField(); i++ {
		name := strings.Split(ty.Field(i).Tag.Get("json"), ",")[0]
		if !strings.Contains(string(raw), "| `"+name+"` |") {
			t.Errorf("the field %q is not in the table of docs/audit-log.md", name)
		}
	}
}
