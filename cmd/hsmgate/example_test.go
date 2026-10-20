package main

import (
	"testing"

	"github.com/zystem/hsmgate/internal/config"
)

// The example in deploy/ must stay a valid configuration.
func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := config.Load("../../deploy/hsmgate.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Keys) != 4 || len(cfg.Clients) != 4 {
		t.Errorf("%d keys, %d clients", len(cfg.Keys), len(cfg.Clients))
	}
}
