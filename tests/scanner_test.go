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

		// Build token fixtures from fragments to avoid committing literal secret signatures.
		stripeSecret := "sk" + "_live_" + "1234567890abcdefghijklmn"
		twilioKey := "S" + "K1234567890abcdef1234567890abcdef"
		squareToken := "sq0" + "atp-" + "1234567890123456789012"

		fmt.Fprintln(w, `
			var googleApiKey = "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX";
			var awsKey = "AKIAIOSFODNN7EXAMPLE";
			var stripeSecret = "%s";
			var githubPat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
			var slackToken = "xoxb-1234567890abcdef1234567890";
			var gitlabPat = "glpat-abcdefghijklmnopqrstuvwxyz12";
			var sendgridApi = "SG.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
			var mailgunApi = "key-1234567890abcdef1234567890abcdef";
			var resendKey = "re_1234567890abcdef12345678";
			var twilioKey = "%s";
			var squareToken = "%s";
			var cloudflareGlobalApiKey = "0123456789abcdef0123456789abcdef01234";
			var cloudflareApiToken = "cf_api_token_AbCdEf0123456789XYZqwert";
			var userApiToken = "usr_tok_AbCdEf0123456789";
			var bearerAuth = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
			var mySecret = "THIS_IS_A_VERY_LONG_SECRET_STRING_DO_NOT_SHARE";
			var importRef = import.meta.env.SUPER_SECRET_TOKEN;
			var privateKey = "-----BEGIN RSA PRIVATE KEY-----";
		`, stripeSecret, twilioKey, squareToken)
	}))
	defer ts.Close()

	// Execute Scan
	leaks, _ := scanner.RunScan(ts.URL, false)

	if len(leaks) == 0 {
		t.Fatalf("Expected leaks to be found, got 0")
	}

	expectedCredentialTypes := []models.LeakType{
		models.LeakTypeGoogleKey,
		models.LeakTypeAWSKey,
		models.LeakTypeStripeKey,
		models.LeakTypeGitHubToken,
		models.LeakTypeSlackToken,
		models.LeakTypeGitLabToken,
		models.LeakTypeSendGridKey,
		models.LeakTypeMailgunKey,
		models.LeakTypeResendKey,
		models.LeakTypeTwilioKey,
		models.LeakTypeSquareToken,
		models.LeakTypeCloudflare,
		models.LeakTypeUserAPIToken,
		models.LeakTypeBearerToken,
		models.LeakTypeRSAPrivate,
	}
	found := make(map[models.LeakType]bool, len(expectedCredentialTypes)+2)

	for _, l := range leaks {
		found[l.LeakType] = true
	}

	for _, leakType := range expectedCredentialTypes {
		if !found[leakType] {
			t.Errorf("Expected to find %s leak in synthetic payload", leakType)
		}
	}

	// Keep prior coverage for non-credential secret metadata detections.
	if !found[models.LeakTypeGenericSec] {
		t.Errorf("Expected to find %s leak in synthetic payload", models.LeakTypeGenericSec)
	}
	if !found[models.LeakTypeImportMeta] {
		t.Errorf("Expected to find %s leak in synthetic payload", models.LeakTypeImportMeta)
	}
}
