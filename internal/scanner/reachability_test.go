package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateTargetReachable_ActiveServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer ts.Close()

	if err := ValidateTargetReachable(ts.URL); err != nil {
		t.Fatalf("expected reachable target, got error: %v", err)
	}
}

func TestValidateTargetReachable_ClosedServerErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	ts.Close() // close immediately; URL should now be unreachable

	if err := ValidateTargetReachable(ts.URL); err == nil {
		t.Fatalf("expected error for unreachable target")
	}
}

