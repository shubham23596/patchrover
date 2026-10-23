package demo

import (
	"bytes"
	"strings"
	"testing"
)

func TestDemoCompletesOfflineWorkflow(t *testing.T) {
	var output bytes.Buffer
	if err := Run(&output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ASSESS  affected", "PROPOSE local diff only", "VERIFY  fixed", "integrity=true", "Demo complete"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("demo output missing %q:\n%s", expected, output.String())
		}
	}
}
