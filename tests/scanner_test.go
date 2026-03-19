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
			var awsKey = "AKIAIOSFODNN7EXAMPLE";
			var mySecret = "THIS_IS_A_VERY_LONG_SECRET_STRING_DO_NOT_SHARE";
			var resendKey = "re_1234567890abcdef12345678";
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

	foundGoogle := false
	foundGeneric := false
	foundImportMeta := false
	foundAWS := false
	foundResend := false

	for _, l := range leaks {
		switch l.LeakType {
		case models.LeakTypeGoogleKey:
			foundGoogle = true
		case models.LeakTypeGenericSec:
			foundGeneric = true
		case models.LeakTypeImportMeta:
			foundImportMeta = true
		case models.LeakTypeAWSKey:
			foundAWS = true
		case models.LeakTypeResendKey:
			foundResend = true
		}
	}

	if !foundResend {
		t.Errorf("Expected to find RESEND_API_KEY leak in synthetic payload")
	}
	if !foundGoogle {
		t.Errorf("Expected to find GOOGLE_API_KEY leak in synthetic payload")
	}
	if !foundGeneric {
		t.Errorf("Expected to find GENERIC_SECRET_KEY leak in synthetic payload")
	}
	if !foundImportMeta {
		t.Errorf("Expected to find IMPORT_META_LEAK leak in synthetic payload")
	}
	if !foundAWS {
		t.Errorf("Expected to find AWS_ACCESS_KEY leak in synthetic payload")
	}
}
