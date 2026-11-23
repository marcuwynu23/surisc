package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name     string
		findings int
		want     int
	}{
		{name: "clean", findings: 0, want: exitOK},
		{name: "findings", findings: 1, want: exitFindings},
		{name: "many findings", findings: 10, want: exitFindings},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.findings); got != tt.want {
				t.Fatalf("exitCodeFor(%d) = %d, want %d", tt.findings, got, tt.want)
			}
		})
	}
}

func TestRunRequiresTarget(t *testing.T) {
	if got := run(nil); got != exitError {
		t.Fatalf("run(nil) = %d, want %d", got, exitError)
	}
}

func TestRunAllowsHelp(t *testing.T) {
	if got := run([]string{"-h"}); got != exitOK {
		t.Fatalf("run(-h) = %d, want %d", got, exitOK)
	}
}

func TestRunRejectsUnknownFlag(t *testing.T) {
	if got := run([]string{"-nope"}); got != exitError {
		t.Fatalf("run(-nope) = %d, want %d", got, exitError)
	}
}

func TestRunRejectsInvalidInformativeScope(t *testing.T) {
	if got := run([]string{"-u", "https://example.com", "-i=bogus"}); got != exitError {
		t.Fatalf("run(invalid -i) = %d, want %d", got, exitError)
	}
}

func TestRunReturnsFindingsExitCode(t *testing.T) {
	stripeSecret := "sk" + "_live_" + "1234567890abcdefghijklmn"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `var stripeSecret = "%s";`, stripeSecret)
	}))
	defer ts.Close()

	if got := run([]string{"-u", ts.URL, "-o", "json"}); got != exitFindings {
		t.Fatalf("run(leaky target) = %d, want %d", got, exitFindings)
	}
}
