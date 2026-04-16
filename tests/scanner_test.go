package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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

		fmt.Fprintf(w, `
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
			var privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu9U8v8iS0D7gA9yJxZ4f3v2wH9m2q3R4t5y6u7i8o9p0a1b2\nc3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6AaBbCcDdEeFfGgHh\n-----END RSA PRIVATE KEY-----";
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

func TestRunScanInformativeIncludesRoutes(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: "+ts.URL+"/sitemap.xml\n")
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<urlset><url><loc>%s/about</loc></url><url><loc>%s/docs/getting-started</loc></url></urlset>`, ts.URL, ts.URL)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `
				<html>
					<body>
						<div id="root"></div>
						<a href="/about">About</a>
						<a href="/docs/getting-started">Docs</a>
						<form action="/auth/login"></form>
						<script src="/assets/app.js"></script>
						<script>const api = "/api/v1/users";</script>
					</body>
				</html>
			`)
		}
	}))
	defer ts.Close()

	leaks, insight := scanner.RunScan(ts.URL, true)
	if len(leaks) != 0 {
		t.Fatalf("Expected no leak scan in informative mode, got %d findings", len(leaks))
	}

	expectedRoutes := []string{
		"/about",
		"/api/v1/users",
		"/assets/app.js",
		"/auth/login",
		"/docs/getting-started",
	}
	for _, route := range expectedRoutes {
		if !slices.Contains(insight.Routes, route) {
			t.Fatalf("Expected route %q in informative routes, got %v", route, insight.Routes)
		}
	}
	if insight.RobotsTxt == "" {
		t.Fatalf("expected robots.txt content in informative insight")
	}
	if insight.SitemapXML == "" {
		t.Fatalf("expected sitemap.xml content in informative insight")
	}
	if insight.SPA == "" || insight.SPA == "No" {
		t.Fatalf("expected SPA to be detected, got %q", insight.SPA)
	}
}
