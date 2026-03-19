package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"surisc/internal/models"
	"surisc/internal/scanner"
)

func TestRunScan(t *testing.T) {
	// Create a mock HTTP server serving a synthetic payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintln(w, `
			var apiKey = "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX";
			var mySecret = "THIS_IS_A_VERY_LONG_SECRET_STRING_DO_NOT_SHARE";
			// Should be ignored due to length and lack of assignment entropy
			var normalVal = "password"; 
			var importRef = import.meta.env.SUPER_SECRET_TOKEN;
		`)
	}))
	defer ts.Close()

	// Execute Scan
	leaks := scanner.RunScan(ts.URL)

	if len(leaks) == 0 {
		t.Fatalf("Expected leaks to be found, got 0")
	}

	foundFirebase := false
	foundGeneric := false
	foundImportMeta := false

	for _, l := range leaks {
		switch l.LeakType {
		case models.LeakTypeFirebaseKey:
			foundFirebase = true
		case models.LeakTypeGenericSec:
			foundGeneric = true
		case models.LeakTypeImportMeta:
			foundImportMeta = true
		}
	}

	if !foundFirebase {
		t.Errorf("Expected to find FIREBASE_API_KEY leak in synthetic payload")
	}
	if !foundGeneric {
		t.Errorf("Expected to find GENERIC_SECRET_KEY leak in synthetic payload")
	}
	if !foundImportMeta {
		t.Errorf("Expected to find IMPORT_META_LEAK leak in synthetic payload")
	}
}
