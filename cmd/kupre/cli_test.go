package main

import (
	"errors"
	"testing"
)

// TestExitErrorCarriesCode verifies the exit contract holds without a process
// boundary. Before commands returned a typed error, this was untestable: they
// called os.Exit from inside a Cobra handler.
func TestExitErrorCarriesCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "blocking findings", err: exitWith(exitBlocked), want: exitBlocked},
		{name: "warnings only", err: exitWith(exitWarnings), want: exitWarnings},
		{name: "tool error", err: exitError{code: exitToolError, err: errors.New("boom")}, want: exitToolError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ee exitError
			if !errors.As(tt.err, &ee) {
				t.Fatalf("%v is not an exitError", tt.err)
			}
			if ee.code != tt.want {
				t.Errorf("code = %d, want %d", ee.code, tt.want)
			}
		})
	}
}

// TestRunRejectsBadInput exercises the real CLI path end to end for inputs that
// need no cluster, confirming argument errors map to the tool-error code.
func TestRunRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "missing target version", args: []string{"check"}, want: exitToolError},
		{name: "unparseable version", args: []string{"check", "--target-version", "nope"}, want: exitToolError},
		{name: "unknown output format", args: []string{
			"check", "--target-version", "1.36.0", "-o", "bogus"}, want: exitToolError},
		{name: "unknown subcommand", args: []string{"frobnicate"}, want: exitToolError},
		{name: "checks needs no cluster", args: []string{"checks"}, want: exitOK},
		{name: "version needs no cluster", args: []string{"version"}, want: exitOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args); got != tt.want {
				t.Errorf("run(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}
