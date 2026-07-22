package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"

	"surisc/internal/models"
)

func TestAnalyzeHeaders_DetectsGoogleKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX") // 35 chars after AIza

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGoogleKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Google API key leak in header")
	}
}

func TestAnalyzeHeaders_DetectsAWSKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Custom-Header", "AKIAIOSFODNN7EXAMPLE")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeAWSKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected AWS key leak in header")
	}
}

func TestAnalyzeHeaders_DetectsStripeKey(t *testing.T) {
	headers := http.Header{}
	stripeTestKey := "sk_" + "live_" + "AAAAAAAAAAAAAAAAAAAAAAAA"
	headers.Set("Authorization", "Bearer "+stripeTestKey)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeStripeKey || l.LeakType == models.LeakTypeBearerToken {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Stripe key or bearer token leak in header")
	}
}

func TestAnalyzeHeaders_DetectsGitHubToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Custom-Header", "ghp_abcdefghijklmnopqrstuvwxyz1234567890")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGitHubToken {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected GitHub token leak in header")
	}
}

func TestAnalyzeHeaders_DetectsSlackToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Custom-Header", "xoxb-1234567890abcdef1234567890")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeSlackToken {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Slack token leak in header")
	}
}

func TestAnalyzeHeaders_DetectsBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeBearerToken {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected bearer token leak in Authorization header")
	}
}

func TestAnalyzeHeaders_DetectsInternalIP(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Forwarded-For", "192.168.1.100")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeInternalIP {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected internal IP leak in header")
	}
}

func TestAnalyzeHeaders_DetectsNamedAPIKeyHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-api-key", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGenericSec {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected generic secret leak for named API key header with high entropy")
	}
}

func TestAnalyzeHeaders_SkipsLowEntropyAPIKeyHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-api-key", "aaaaaaaaaaaaaaaaaaaa")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGenericSec {
			t.Fatalf("unexpected generic secret leak for low entropy header value: %q", l.Snippet)
		}
	}
}

func TestAnalyzeHeaders_NoMatchReturnsNoLeaks(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Type", "text/html")
	headers.Set("Cache-Control", "no-cache")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	if len(leaks) != 0 {
		t.Fatalf("expected no leaks for benign headers, got %d", len(leaks))
	}
}

func TestAnalyzeHeaders_DetectsMailgunKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Custom-Header", "key-1234567890abcdef1234567890abcdef")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeMailgunKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Mailgun key leak in header")
	}
}

func TestAnalyzeHeaders_DetectsTwilioKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Custom-Header", "SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeTwilioKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Twilio key leak in header")
	}
}

func TestAnalyzeHeaders_MultipleHeaderValues(t *testing.T) {
	headers := http.Header{}
	headers.Add("Set-Cookie", "session=abc123")
	headers.Add("Set-Cookie", "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890")

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeHeaders("https://example.com/api", &headers, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGitHubToken {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected GitHub token leak in multi-value header")
	}
}

func TestClassifySPAFromHTML_Positive(t *testing.T) {
	tests := []struct {
		name  string
		html  string
		spaID string
	}{
		{"root div", `<html><body><div id="root"></div></body></html>`, "Yes"},
		{"app div", `<html><body><div id="app"></div></body></html>`, "Yes"},
		{"next id", `<html><body><div id="__next"></div></body></html>`, "Yes"},
		{"module script", `<html><body><script type="module" src="app.js"></script></body></html>`, "Yes"},
		{"single quotes", `<html><body><div id='app'></div></body></html>`, "Yes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifySPAFromHTML([]byte(tt.html))
			if result != tt.spaID {
				t.Errorf("classifySPAFromHTML(%q) = %q, want %q", tt.html, result, tt.spaID)
			}
		})
	}
}

func TestClassifySPAFromHTML_Negative(t *testing.T) {
	html := `<html><body><h1>Plain HTML</h1><p>No SPA markers here</p></body></html>`
	result := classifySPAFromHTML([]byte(html))
	if result != "No" {
		t.Errorf("classifySPAFromHTML() = %q, want %q", result, "No")
	}
}

func TestClassifyPWA(t *testing.T) {
	tests := []struct {
		name   string
		routes []string
		want   string
	}{
		{"both manifest and sw", []string{"/manifest.json", "/sw.js"}, "Yes"},
		{"manifest only", []string{"/manifest.webmanifest", "/about"}, "Likely"},
		{"sw only", []string{"/registerSW.js", "/api/users"}, "Likely"},
		{"neither", []string{"/index.html", "/about"}, "No"},
		{"empty", nil, "No"},
		{"service-worker path", []string{"/service-worker.js"}, "Likely"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyPWA(tt.routes)
			if got != tt.want {
				t.Errorf("classifyPWA(%v) = %q, want %q", tt.routes, got, tt.want)
			}
		})
	}
}

func TestIsLikelyPlaceholderValue(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"your-api-key-here", true},
		{"your_client_secret", true},
		{"example-secret", true},
		{"sample_token_123", true},
		{"dummy_value", true},
		{"test_secret_key", true},
		{"changeme", true},
		{"real-credential-value", false},
		{"AKIAIOSFODNN7EXAMPLE", false},
		{"AIzaSyCXwabcde1234567890", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			got := isLikelyPlaceholderValue(tt.val)
			if got != tt.want {
				t.Errorf("isLikelyPlaceholderValue(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestIsLikelyNonSecretHighEntropy(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"19qfcMTGFlcK6Gl5h9PmlJd3DubeFdiOz", true},
		{"1BbiTxGrWqiEevyxGLX1Ypyto4eA1hSz2", true},
		{"AKIAIOSFODNN7EXAMPLE", false},
		{"1234567890123456789012345678901234567890", true},
		{"abcdefghijklmnopqrstuvwxyz1234567890", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			got := isLikelyNonSecretHighEntropy(tt.val)
			if got != tt.want {
				t.Errorf("isLikelyNonSecretHighEntropy(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestIsLikelyRouteValue(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"/api/users", true},
		{"/auth/login", true},
		{"./relative/path", true},
		{"../relative/path", true},
		{"sk_" + "live_" + "abc123def456", false},
		{"AKIAIOSFODNN7EXAMPLE", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			got := isLikelyRouteValue(tt.val)
			if got != tt.want {
				t.Errorf("isLikelyRouteValue(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestIsCrawlableResourceRef(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"/assets/app.js", true},
		{"https://cdn.example.com/lib.js", true},
		{"//cdn.example.com/lib.js", true},
		{"data:text/javascript;base64,Zm9v", false},
		{"javascript:void(0)", false},
		{"", false},
		{"   ", false},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := isCrawlableResourceRef(tt.ref)
			if got != tt.want {
				t.Errorf("isCrawlableResourceRef(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestIsLikelyRealRoute(t *testing.T) {
	tests := []struct {
		route string
		want  bool
	}{
		{"/api/users", true},
		{"/dashboard", true},
		{"/:id", false},
		{"/:id/edit", false},
		{"/etc/nginx/sites-available", false},
		{"/src/content/articles/demo.md", false},
		{"/home/user/file.pem", false},
		{"/opt/app/config.crt", false},
		{"{id}", false},
		{"<id>", false},
		{"/path,with,commas", false},
		{"/path\\with\\backslash", false},
	}
	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			got := isLikelyRealRoute(tt.route)
			if got != tt.want {
				t.Errorf("isLikelyRealRoute(%q) = %v, want %v", tt.route, got, tt.want)
			}
		})
	}
}

func TestIsLikelyWordPressBody(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{`wp-content/themes/main.js`, true},
		{`wp-includes/css/style.css`, true},
		{`wp-json`, true},
		{`xmlrpc.php`, true},
		{`<meta name="generator" content="WordPress 6.0" />`, true},
		{`<html><body><p>Just some article about wordpress</p></body></html>`, false},
		{`const wordpress = "cool";`, false},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			s := strings.ToLower(tt.body)
			got := isLikelyWordPressBody(s)
			if got != tt.want {
				t.Errorf("isLikelyWordPressBody(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestIsLikelyFallbackResponse(t *testing.T) {
	tests := []struct {
		name       string
		contentType string
		sig        string
		homeSig    string
		missingSig string
		want       bool
	}{
		{"matches home", "text/html", "abc123", "abc123", "", true},
		{"matches missing", "text/html", "abc123", "", "abc123", true},
		{"non-html", "application/json", "abc123", "abc123", "", false},
		{"no match", "text/html", "abc123", "def456", "ghi789", false},
		{"empty sig", "text/html", "", "abc123", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyFallbackResponse(tt.contentType, tt.sig, tt.homeSig, tt.missingSig)
			if got != tt.want {
				t.Errorf("isLikelyFallbackResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDedupeLeaks(t *testing.T) {
	leaks := []models.Leak{
		{LeakType: models.LeakTypeGoogleKey, SourceURL: "https://example.com", Snippet: "AIzaSyA"},
		{LeakType: models.LeakTypeGoogleKey, SourceURL: "https://example.com", Snippet: "AIzaSyA"},
		{LeakType: models.LeakTypeAWSKey, SourceURL: "https://example.com", Snippet: "AKIA1234"},
	}
	result := dedupeLeaks(leaks)
	if len(result) != 2 {
		t.Fatalf("expected 2 deduped leaks, got %d", len(result))
	}
}

func TestBoundedWorkerCount(t *testing.T) {
	maxWorkers := runtime.NumCPU() * 2
	if maxWorkers < 4 {
		maxWorkers = 4
	}
	if maxWorkers > 24 {
		maxWorkers = 24
	}

	tests := []struct {
		n    int
		name string
	}{
		{0, "zero"},
		{1, "one"},
		{4, "four"},
		{10, "ten"},
		{100, "large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundedWorkerCount(tt.n)
			if got < 1 {
				t.Errorf("boundedWorkerCount(%d) = %d, want >= 1", tt.n, got)
			}
			if got > maxWorkers {
				t.Errorf("boundedWorkerCount(%d) = %d, want <= %d", tt.n, got, maxWorkers)
			}
			if got > tt.n && tt.n > 0 {
				t.Errorf("boundedWorkerCount(%d) = %d, want <= %d", tt.n, got, tt.n)
			}
		})
	}
}

func TestBoundedWorkerCount_ProducesExpectedValue(t *testing.T) {
	got := boundedWorkerCount(100)
	maxExpected := runtime.NumCPU() * 2
	if maxExpected > 24 {
		maxExpected = 24
	}
	if maxExpected < 4 {
		maxExpected = 4
	}
	if got != maxExpected {
		t.Errorf("boundedWorkerCount(100) = %d, want %d (8 CPUs → 16 max)", got, maxExpected)
	}
}

func TestHostingRank(t *testing.T) {
	tests := []struct {
		hosting string
		want    int
	}{
		{"Cloudflare Workers", 100},
		{"Cloudflare Pages", 100},
		{"Cloudflare Proxied", 70},
		{"Vercel", 90},
		{"Heroku", 90},
		{"", 90},
	}
	for _, tt := range tests {
		t.Run(tt.hosting, func(t *testing.T) {
			got := hostingRank(tt.hosting)
			if got != tt.want {
				t.Errorf("hostingRank(%q) = %d, want %d", tt.hosting, got, tt.want)
			}
		})
	}
}

func TestShouldUpgradeHosting(t *testing.T) {
	tests := []struct {
		current string
		next    string
		want    bool
	}{
		{"", "Vercel", true},
		{"Vercel", "", false},
		{"Vercel", "Cloudflare Pages", true},
		{"Cloudflare Pages", "Vercel", false},
		{"Cloudflare Proxied", "Cloudflare Pages", true},
		{"Cloudflare Pages", "Cloudflare Proxied", false},
	}
	for _, tt := range tests {
		t.Run(tt.current+"->"+tt.next, func(t *testing.T) {
			got := shouldUpgradeHosting(tt.current, tt.next)
			if got != tt.want {
				t.Errorf("shouldUpgradeHosting(%q, %q) = %v, want %v", tt.current, tt.next, got, tt.want)
			}
		})
	}
}

func TestHasCloudflarePagesCodeSignal(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{`<meta name="generator" content="Cloudflare Pages">`, true},
		{`<!-- Cloudflare Pages -->`, true},
		{`deployed on cloudflare pages`, true},
		{`<html><body>Plain page</body></html>`, false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := hasCloudflarePagesCodeSignal([]byte(tt.body))
			if got != tt.want {
				t.Errorf("hasCloudflarePagesCodeSignal(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestHasOriginServerFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"x-powered-by php", http.Header{"X-Powered-By": {"PHP/7.4"}}, true},
		{"x-drupal-cache", http.Header{"X-Drupal-Cache": {"MISS"}}, true},
		{"cloudflare pages powered", http.Header{"X-Powered-By": {"Cloudflare Pages"}}, false},
		{"no origin headers", http.Header{"Cf-Ray": {"abc123"}}, false},
		{"x-aspnet-version", http.Header{"X-Aspnet-Version": {"4.0.30319"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasOriginServerFingerprint(tt.header)
			if got != tt.want {
				t.Errorf("hasOriginServerFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapKeys(t *testing.T) {
	set := map[string]struct{}{
		"b": {},
		"a": {},
		"c": {},
	}
	keys := mapKeys(set)
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("expected sorted keys [a b c], got %v", keys)
	}
}

func TestMapKeysEmpty(t *testing.T) {
	keys := mapKeys(nil)
	if keys != nil {
		t.Fatalf("expected nil for empty set, got %v", keys)
	}
}

func TestSortedRoutes(t *testing.T) {
	set := map[string]struct{}{
		"/api/users": {},
		"/admin":     {},
		"/about":     {},
	}
	routes := sortedRoutes(set)
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0] != "/about" || routes[1] != "/admin" || routes[2] != "/api/users" {
		t.Fatalf("expected sorted routes, got %v", routes)
	}
}

func TestSortedRoutesEmpty(t *testing.T) {
	routes := sortedRoutes(nil)
	if routes != nil {
		t.Fatalf("expected nil for empty set, got %v", routes)
	}
}

func TestSortedTech(t *testing.T) {
	set := map[string]struct{}{
		"React":   {},
		"Angular": {},
		"Vue":     {},
	}
	tech := sortedTech(set)
	if len(tech) != 3 {
		t.Fatalf("expected 3 tech, got %d", len(tech))
	}
	if tech[0] != "Angular" || tech[1] != "React" || tech[2] != "Vue" {
		t.Fatalf("expected sorted tech, got %v", tech)
	}
}

func TestSortedTechEmpty(t *testing.T) {
	tech := sortedTech(nil)
	if tech != nil {
		t.Fatalf("expected nil for empty set, got %v", tech)
	}
}

func TestEnsureVanillaFrontend(t *testing.T) {
	tests := []struct {
		front []string
		want  bool
	}{
		{[]string{}, true},
		{[]string{"React"}, false},
		{[]string{"Vanilla JS"}, true},
		{[]string{"Alpine.js"}, false},
		{[]string{"CustomLib"}, true},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := ensureVanillaFrontend(tt.front)
			hasVanilla := false
			for _, f := range result {
				if f == "Vanilla JS" {
					hasVanilla = true
					break
				}
			}
			if hasVanilla != tt.want {
				t.Errorf("ensureVanillaFrontend(%v) = %v, vanilla present = %v, want %v", tt.front, result, hasVanilla, tt.want)
			}
		})
	}
}

func TestCookiesFromHeader(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; HttpOnly; Secure")
	h.Add("Set-Cookie", "token=xyz789; SameSite=Lax")

	cookies := cookiesFromHeader(&h)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
}

func TestCookiesFromHeaderNil(t *testing.T) {
	cookies := cookiesFromHeader(nil)
	if cookies != nil {
		t.Fatalf("expected nil for nil header, got %v", cookies)
	}
}

func TestMergeCookieInsights(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "session", Value: "abc123", HttpOnly: true, Secure: true},
		{Name: "jwt_token", Value: "eyJhbGciOiJIUzI1NiJ9.payload.signature"},
		{Name: "tracking", Value: "abc", SameSite: http.SameSiteLaxMode},
	}

	var insight models.TechInsight
	mergeCookieInsights(cookies, &insight)

	if len(insight.CookieSecurity) == 0 {
		t.Fatal("expected cookie security findings")
	}
	if len(insight.JWTIndicators) == 0 {
		t.Fatal("expected JWT indicators")
	}
}

func TestNormalizeBodyForComparison(t *testing.T) {
	body := `  <html>
		<body>Hello /api/users world</body>
	</html> `
	paths := []string{"/api/users", "/admin"}
	result := normalizeBodyForComparison(body, paths)
	if len(result) == 0 {
		t.Fatal("expected non-empty normalized body")
	}
}

func TestResponseSignature(t *testing.T) {
	sig1 := responseSignature("text/html", []byte("<html>ok</html>"))
	sig2 := responseSignature("text/html", []byte("<html>ok</html>"))
	sig3 := responseSignature("application/json", []byte("{}"))
	if sig1 == "" {
		t.Fatal("expected non-empty signature")
	}
	if sig1 != sig2 {
		t.Fatal("expected same signature for identical inputs")
	}
	if sig1 == sig3 {
		t.Fatal("expected different signature for different inputs")
	}
}

func TestStripMarkdownFencedCodeBlocks(t *testing.T) {
	input := []byte("outside\n```bash\necho \"inside\"\n```\noutside2")
	result := stripMarkdownFencedCodeBlocks(input)
	resultStr := string(result)
	if strings.Contains(resultStr, "inside") {
		t.Fatal("expected fenced code block content to be stripped")
	}
	if !strings.Contains(resultStr, "outside") {
		t.Fatal("expected outside content to remain")
	}
}

func TestAddRoute(t *testing.T) {
	baseURL, _ := url.Parse("https://example.com")
	routeSet := make(map[string]struct{})
	var mu sync.Mutex

	addRoute("/api/users", baseURL, routeSet, &mu)
	if _, ok := routeSet["/api/users"]; !ok {
		t.Fatal("expected /api/users to be added")
	}

	addRoute("https://external.com/evil", baseURL, routeSet, &mu)
	if _, ok := routeSet["/evil"]; ok {
		t.Fatal("expected external URL route to be skipped (different host)")
	}

	addRoute("", baseURL, routeSet, &mu)
	addRoute("#fragment", baseURL, routeSet, &mu)
	addRoute("javascript:void(0)", baseURL, routeSet, &mu)
	addRoute("data:text/html,hi", baseURL, routeSet, &mu)
}

func TestShannonEntropyEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		min   float64
		max   float64
	}{
		{"", 0, 0},
		{"a", 0, 0},
		{"aaaaa", 0, 0.5},
		{"abcdefghijklmnopqrstuvwxyz", 4.0, 5.0},
		{"AIzaSyCXwabcde1234567890fghijkLMNOPQrsX", 3.5, 5.5},
		{"AKIAIOSFODNN7EXAMPLE", 3.0, 4.5},
		{"0123456789abcdef", 3.5, 4.5},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			ent := shannonEntropy(tt.input)
			if ent < tt.min || ent > tt.max {
				t.Errorf("shannonEntropy(%q) = %f, want between %f and %f", tt.input, ent, tt.min, tt.max)
			}
		})
	}
}

func TestTruncateEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		limit int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc..."},
		{"abcde", 4, "abcd..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := truncate(tt.input, tt.limit)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.limit, got, tt.want)
			}
		})
	}
}

func TestHasCloudflarePagesHeaderSignal(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{
			"not enough signals",
			http.Header{
				"Server":        {"cloudflare"},
				"Cf-Ray":        {"abc123-LAX"},
				"Cache-Control": {"public, max-age=0, must-revalidate"},
			},
			false,
		},
		{
			"origin server fingerprint overrides",
			http.Header{
				"Server":        {"cloudflare"},
				"Cf-Ray":        {"abc123-LAX"},
				"X-Powered-By":  {"PHP/7.4"},
			},
			false,
		},
		{
			"all signals present",
			http.Header{
				"Server":                    {"cloudflare"},
				"Cf-Ray":                    {"abc123-LAX"},
				"Cf-Cache-Status":           {"HIT"},
				"Cache-Control":             {"public, max-age=0, must-revalidate"},
				"Speculation-Rules":         {`"/cdn-cgi/speculation"`},
				"Strict-Transport-Security": {"max-age=15552000; preload"},
			},
			true,
		},
		{
			"no cloudflare edge",
			http.Header{
				"Server": {"nginx"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCloudflarePagesHeaderSignal(tt.header)
			if got != tt.want {
				t.Errorf("hasCloudflarePagesHeaderSignal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddTech(t *testing.T) {
	techSet := make(map[string]struct{})
	var mu sync.Mutex

	addTech("React", techSet, &mu)
	if _, ok := techSet["React"]; !ok {
		t.Fatal("expected React to be added")
	}

	addTech("", techSet, &mu)
	if len(techSet) != 1 {
		t.Fatal("expected empty string to not add")
	}
}

func TestAddTechFromURL(t *testing.T) {
	techSet := make(map[string]struct{})
	var mu sync.Mutex

	addTechFromURL("/_next/static/chunk.js", techSet, &mu)
	if _, ok := techSet["Next.js"]; !ok {
		t.Fatal("expected Next.js from URL")
	}
	if _, ok := techSet["React"]; !ok {
		t.Fatal("expected React from Next.js URL")
	}
}

func TestAnalyzeContent_DetectsAllSecretTypes(t *testing.T) {
	stripeSecret := "sk_" + "live_" + "AAAAAAAAAAAAAAAAAAAAAAAA"
	content := []byte(fmt.Sprintf(`
		var googleApiKey = "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX";
		var awsKey = "AKIAIOSFODNN7EXAMPLE";
		var stripeKey = "%s";
		var githubPat = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
		var slackToken = "xoxb-1234567890abcdef1234567890";
		var gitlabPat = "glpat-abcdefghijklmnopqrstuvwxyz12";
		sendgrid: "SG.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
		mailgunKey = "key-1234567890abcdef1234567890abcdef";
		resendKey = "re_1234567890abcdef12345678";
		twilioKey = "SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		squareToken = "sq0atp-AAAAAAAAAAAAAAAAAAAAAAAAAA";
		cloudflareGlobalKey = "0123456789abcdef0123456789abcdef01234";
		userApiToken = "usr_tok_AbCdEf0123456789";
		bearer = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGVzdA";
		internalIP = "192.168.1.1";
		import.meta.env.SECRET_TOKEN;
		secret = "THIS_IS_A_VERY_LONG_SECRET_STRING_DO_NOT_SHARE";
		var privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu9U8v8iS0D7gA9yJxZ4f3v2wH9m2q3R4t5y6u7i8o9p0a1b2\nc3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6AaBbCcDdEeFfGgHh\n-----END RSA PRIVATE KEY-----";
	`, stripeSecret))

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	expected := []models.LeakType{
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
		models.LeakTypeInternalIP,
		models.LeakTypeImportMeta,
		models.LeakTypeGenericSec,
		models.LeakTypeRSAPrivate,
	}

	found := make(map[models.LeakType]bool)
	for _, l := range leaks {
		found[l.LeakType] = true
	}

	for _, et := range expected {
		if !found[et] {
			t.Errorf("expected leak type %s not found", et)
		}
	}
}

func TestAnalyzeContent_SkipsBenignContent(t *testing.T) {
	content := []byte(`
		const name = "John";
		const age = 30;
		const city = "New York";
		console.log("Hello World");
	`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/script.js", content, &leaks, &mu)

	if len(leaks) != 0 {
		t.Fatalf("expected no leaks for benign content, got %d", len(leaks))
	}
}

func TestAnalyzeContent_DetectsFirebaseConfig(t *testing.T) {
	content := []byte(`var firebaseConfig = { apiKey: "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX" };`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/app.js", content, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeFirebaseConfig {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Firebase config leak")
	}
}

func TestAnalyzeContent_DetectsFirebaseInit(t *testing.T) {
	content := []byte(`firebase.initializeApp({ apiKey: "AIzaSyCXwabcde1234567890fghijkLMNOPQrsX" });`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/app.js", content, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeFirebaseConfig {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Firebase config leak from initializeApp")
	}
}

func TestAnalyzeContent_DetectsSupabaseConfig(t *testing.T) {
	content := []byte(`
		var supabaseUrl = "https://abcproject.supabase.co";
		var supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dGVzdA";
	`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/app.js", content, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeSupabaseConfig {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected Supabase config leak")
	}
}

func TestAnalyzeContent_DetectsMapFileReference(t *testing.T) {
	content := []byte(`//# sourceMappingURL=https://example.com/app.js.map`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/app.js", content, &leaks, &mu)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeMapFile {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected map file reference leak")
	}
}

func TestAnalyzeContent_SkipsReactInternalSecrets(t *testing.T) {
	content := []byte(`SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/react.js", content, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGenericSec {
			t.Fatalf("unexpected generic secret leak for React internal: %q", l.Snippet)
		}
	}
}

func TestAnalyzeContent_SkipsWASMHeader(t *testing.T) {
	content := []byte(`AGFzbQEAAAAAAA==`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/module.wasm", content, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeHighEntropy {
			t.Fatalf("unexpected high entropy leak for WASM header: %q", l.Snippet)
		}
	}
}

func TestAnalyzeContent_SkipsAlphabetString(t *testing.T) {
	content := []byte(`"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/lib.js", content, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeHighEntropy {
			t.Fatalf("unexpected high entropy leak for alphabet string: %q", l.Snippet)
		}
	}
}

func TestAnalyzeContent_FiltersRoutePathInPasswordAssignment(t *testing.T) {
	content := []byte(`const PASSWORD = "/auth/sign-in";`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/routes.js", content, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGenericSec {
			t.Fatalf("unexpected generic secret leak for route path: %q", l.Snippet)
		}
	}
}

func TestAnalyzeContent_FiltersPlaceholderSecrets(t *testing.T) {
	content := []byte(`const secret = "your-api-key-here";`)

	var leaks []models.Leak
	var mu sync.Mutex
	analyzeContent("https://example.com/config.js", content, &leaks, &mu)

	for _, l := range leaks {
		if l.LeakType == models.LeakTypeGenericSec {
			t.Fatalf("unexpected generic secret leak for placeholder: %q", l.Snippet)
		}
	}
}

func TestAnalyzeCSP_Table(t *testing.T) {
	tests := []struct {
		name    string
		csp     string
		want    []string
		wantCnt int
	}{
		{"missing header", "", []string{"missing"}, 1},
		{"unsafe-inline in script-src", "default-src 'self'; script-src 'unsafe-inline' 'self'", []string{"unsafe-inline"}, 2},
		{"unsafe-inline in default-src", "default-src 'unsafe-inline' 'self'", []string{"unsafe-inline"}, 2},
		{"unsafe-eval in script-src", "default-src 'self'; script-src 'unsafe-eval'", []string{"unsafe-eval"}, 2},
		{"unsafe-inline + unsafe-eval combo", "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'", []string{"unsafe-inline", "unsafe-eval"}, 2},
		{"missing object-src", "default-src 'self'; script-src 'self'", []string{"object-src"}, 1},
		{"case insensitive unsafe-inline", "default-src 'self'; Script-Src 'Unsafe-Inline'", []string{"unsafe-inline"}, 2},
		{"strict-dynamic still missing object-src", "script-src 'strict-dynamic' 'self'", []string{"object-src"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			h := http.Header{}
			if tt.csp != "" {
				h.Set("Content-Security-Policy", tt.csp)
			}
			analyzeCSP(h, "https://example.com", &localLeaks)
			if len(localLeaks) < tt.wantCnt {
				t.Fatalf("expected >= %d CSP leaks, got %d", tt.wantCnt, len(localLeaks))
			}
			for _, want := range tt.want {
				found := false
				for _, l := range localLeaks {
					if l.LeakType == models.LeakTypeWeakCSP && strings.Contains(l.Snippet, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected CSP leak snippet containing %q (found %d leaks)", want, len(localLeaks))
				}
			}
		})
	}
}

func TestAnalyzeCSP_Secure(t *testing.T) {
	securePolicies := []struct {
		name string
		csp  string
	}{
		{"default-none + explicit object-src", "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'"},
		{"no unsafe-* directives", "default-src 'self'; script-src 'self'; object-src 'self'"},
		{"nonce-based CSP with object-src", "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'self'"},
	}
	for _, tt := range securePolicies {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			h := http.Header{}
			h.Set("Content-Security-Policy", tt.csp)
			analyzeCSP(h, "https://example.com", &localLeaks)
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeWeakCSP {
					t.Fatalf("unexpected CSP leak for secure policy %q: %s", tt.name, l.Snippet)
				}
			}
		})
	}
}

func TestAnalyzeCORS_Table(t *testing.T) {
	tests := []struct {
		name         string
		origin       string
		creds        string
		wantLeak     bool
		wantCredHint bool
	}{
		{"wildcard with credentials true", "*", "true", true, true},
		{"wildcard with credentials false", "*", "false", true, false},
		{"wildcard no credentials header", "*", "", true, false},
		{"specific origin with credentials", "https://trusted.com", "true", false, false},
		{"specific origin without credentials", "https://trusted.com", "", false, false},
		{"no ACAO header", "", "", false, false},
		{"no ACAO with credentials header only", "", "true", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			h := http.Header{}
			if tt.origin != "" {
				h.Set("Access-Control-Allow-Origin", tt.origin)
			}
			if tt.creds != "" {
				h.Set("Access-Control-Allow-Credentials", tt.creds)
			}
			analyzeCORS(h, "https://example.com", &localLeaks)
			hasLeak := false
			hasCredHint := false
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeCORMisconfig {
					hasLeak = true
					if strings.Contains(l.Snippet, "Allow-Credentials") {
						hasCredHint = true
					}
				}
			}
			if hasLeak != tt.wantLeak {
				t.Errorf("expected leak=%v, got leak=%v", tt.wantLeak, hasLeak)
			}
			if hasCredHint != tt.wantCredHint {
				t.Errorf("expected credential hint=%v, got=%v", tt.wantCredHint, hasCredHint)
			}
		})
	}
}

func TestAnalyzeCookieSecurity_Table(t *testing.T) {
	tests := []struct {
		name    string
		cookies []string
		wantMin int
		wantNil bool
	}{
		{"bare cookie no flags", []string{"session=abc123; Path=/"}, 2, false},
		{"all flags present", []string{"session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"}, 0, true},
		{"multiple cookies some insecure", []string{"session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax", "tracking=xyz; Path=/"}, 2, false},
		{"HttpOnly without Secure", []string{"session=abc123; Path=/; HttpOnly"}, 1, false},
		{"Secure without HttpOnly", []string{"session=abc123; Path=/; Secure"}, 1, false},
		{"SameSite=None with missing HttpOnly and Secure", []string{"session=abc123; Path=/; SameSite=None"}, 2, false},
		{"SameSite=Strict with all flags", []string{"session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"}, 0, true},
		{"empty set-cookie value", []string{""}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			h := http.Header{}
			for _, c := range tt.cookies {
				h.Add("Set-Cookie", c)
			}
			analyzeCookieSecurity(h, "https://example.com", &localLeaks)
			if tt.wantNil {
				for _, l := range localLeaks {
					if l.LeakType == models.LeakTypeCookieHardening {
						t.Fatalf("unexpected cookie hardening leak: %s", l.Snippet)
					}
				}
			} else if len(localLeaks) < tt.wantMin {
				t.Fatalf("expected >= %d cookie hardening leaks, got %d", tt.wantMin, len(localLeaks))
			}
		})
	}
}

func TestAnalyzeSRI_Table(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantCnt int
	}{
		{"script without integrity", `<script src="https://cdn.example.com/app.js"></script>`, 1},
		{"link stylesheet without integrity", `<link rel="stylesheet" href="https://cdn.example.com/style.css">`, 1},
		{"both script and link without integrity", `<script src="https://cdn.example.com/app.js"></script><link rel="stylesheet" href="https://cdn.example.com/style.css">`, 2},
		{"script with integrity present", `<script src="https://cdn.example.com/app.js" integrity="sha384-abc123"></script>`, 0},
		{"link with integrity present", `<link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha384-def456">`, 0},
		{"mixed some with some without integrity", `<script src="https://cdn.example.com/secure.js" integrity="sha384-abc"></script><script src="https://cdn.example.com/no-integrity.js"></script>`, 1},
		{"inline script no src", `<script>alert(1)</script>`, 0},
		{"empty src attribute", `<script src=""></script>`, 0},
		{"self-closing script tag", `<script src="https://cdn.example.com/app.js"/>`, 1},
		{"same-origin script without integrity", `<script src="/js/app.js"></script>`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			analyzeMissingSRI(tt.body, "https://example.com", &localLeaks)
			cnt := 0
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeMissingSRI {
					cnt++
				}
			}
			if cnt != tt.wantCnt {
				t.Errorf("expected %d SRI leaks, got %d", tt.wantCnt, cnt)
			}
		})
	}
}

func TestAnalyzeXSSSinks_Table(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantCnt int
	}{
		{"innerHTML assignment", `el.innerHTML = userInput;`, 1},
		{"outerHTML assignment", `el.outerHTML = "<div>" + data + "</div>";`, 1},
		{"eval call", `eval(code);`, 1},
		{"document.write", `document.write(html);`, 1},
		{"document.open", `document.open();`, 1},
		{"insertAdjacentHTML", `el.insertAdjacentHTML('beforeend', html);`, 1},
		{"multiple different sinks", `a.innerHTML = x; eval(code); document.write(html);`, 3},
		{"case insensitive innerHtml", `el.innerHtml = data;`, 1},
		{"clean textContent - no leak", `el.textContent = userInput;`, 0},
		{"clean innerText - no leak", `el.innerText = userInput;`, 0},
		{"clean setAttribute - no leak", `el.setAttribute("data-name", value);`, 0},
		{"no sinks at all", `function add(a, b) { return a + b; }`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			analyzeXSSSinks(tt.body, "https://example.com", &localLeaks)
			cnt := 0
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeXSSSink {
					cnt++
				}
			}
			if cnt != tt.wantCnt {
				t.Errorf("expected %d XSS sink leaks, got %d", tt.wantCnt, cnt)
			}
		})
	}
}

func TestAnalyzeOpenRedirect_Table(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantCnt int
	}{
		{"window.location = params.redirect", `window.location = params.redirect;`, 1},
		{"window.location.href from params.url", `window.location.href = params.url;`, 1},
		{"window.location.href from query.next", `window.location.href = query.next;`, 1},
		{"variable named redirect used in assignment", `var url = getParam("redirect"); window.location = url;`, 1},
		{"hardcoded string var - no leak", `window.location.href = "/dashboard";`, 0},
		{"hardcoded absolute - no leak", `window.location.href = "https://trusted.com/page";`, 0},
		{"window.location.reload - no leak", `window.location.reload();`, 0},
		{"case insensitive Location", `window.LOCATION = params.redirect;`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			analyzeOpenRedirect(tt.body, "https://example.com", &localLeaks)
			cnt := 0
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeOpenRedirect {
					cnt++
				}
			}
			if cnt != tt.wantCnt {
				t.Errorf("expected %d open redirect leaks, got %d", tt.wantCnt, cnt)
			}
		})
	}
}

func TestAnalyzeInsecureForms_Table(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantCnt int
	}{
		{"http form action", `<form action="http://example.com/login" method="POST">`, 1},
		{"https form action - no leak", `<form action="https://example.com/login" method="POST">`, 0},
		{"empty action - no leak", `<form action="">`, 0},
		{"no action attribute - no leak", `<form method="POST">`, 0},
		{"protocol-relative action - no leak", `<form action="//example.com/login">`, 0},
		{"multiple forms one insecure", `<form action="https://example.com/login"></form><form action="http://evil.com/login"></form>`, 1},
		{"uppercase HTTP", `<form action="HTTP://example.com/login">`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			analyzeInsecureForms(tt.body, "https://example.com", &localLeaks)
			cnt := 0
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeInsecureForm {
					cnt++
				}
			}
			if cnt != tt.wantCnt {
				t.Errorf("expected %d insecure form leaks, got %d", tt.wantCnt, cnt)
			}
		})
	}
}

func TestAnalyzeVulnerableCDN_Table(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantCnt int
	}{
		{"jQuery via cdnjs", `<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.0.0/jquery.min.js"></script>`, "jQuery", 1},
		{"Angular via cdnjs", `<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>`, "Angular", 1},
		{"React via unpkg", `<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>`, "React", 1},
		{"Vue via cdn.jsdelivr", `<script src="https://cdn.jsdelivr.net/npm/vue@2.7.14/dist/vue.min.js"></script>`, "Vue", 1},
		{"Bootstrap via maxcdn", `<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">`, "Bootstrap", 1},
		{"Lodash via cdnjs", `<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>`, "Lodash", 1},
		{"multiple known libs", `<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.0.0/jquery.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>`, "jQuery|Lodash", 2},
		{"local script - no leak", `<script src="/js/app.js"></script>`, "", 0},
		{"unknown CDN host - no leak", `<script src="https://mycdn.example.com/jquery/3.0.0/jquery.min.js"></script>`, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var localLeaks []models.Leak
			analyzeVulnerableCDN(tt.body, "https://example.com", &localLeaks)
			cnt := 0
			for _, l := range localLeaks {
				if l.LeakType == models.LeakTypeVulnCDN {
					cnt++
				}
			}
			if cnt != tt.wantCnt {
				t.Errorf("expected %d vulnerable CDN leaks, got %d", tt.wantCnt, cnt)
			}
		})
	}
}

func TestAnalyzeFrontendSecurity_Integration(t *testing.T) {
	var leaks []models.Leak
	var mu sync.Mutex

	headers := http.Header{}
	headers.Set("Content-Type", "text/html")
	headers.Set("Set-Cookie", "session=abc123; Path=/")
	headers.Set("Access-Control-Allow-Origin", "*")

	body := []byte(`<html>
<head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.0.0/jquery.min.js"></script>
</head>
<body>
<form action="http://example.com/login" method="POST"></form>
<script>document.getElementById("x").innerHTML = userInput;</script>
</body>
</html>`)

	analyzeFrontendSecurity("https://example.com", headers, body, &leaks, &mu)

	if len(leaks) == 0 {
		t.Fatal("expected at least one frontend security leak")
	}

	types := map[models.LeakType]bool{}
	for _, l := range leaks {
		types[l.LeakType] = true
	}

	expectTypes := []models.LeakType{
		models.LeakTypeWeakCSP,
		models.LeakTypeCORMisconfig,
		models.LeakTypeCookieHardening,
		models.LeakTypeMissingSRI,
		models.LeakTypeXSSSink,
		models.LeakTypeInsecureForm,
		models.LeakTypeVulnCDN,
	}
	for _, et := range expectTypes {
		if !types[et] {
			t.Errorf("expected frontend leak type %q not found", et)
		}
	}
}

func TestAnalyzeFrontendSecurity_JSContent(t *testing.T) {
	var leaks []models.Leak
	var mu sync.Mutex

	headers := http.Header{}
	headers.Set("Content-Type", "application/javascript")

	body := []byte(`function processData(input) {
	eval(input);
	document.getElementById("output").innerHTML = input;
}`)

	analyzeFrontendSecurity("https://example.com/app.js", headers, body, &leaks, &mu)

	foundXSS := false
	foundRedirect := false
	for _, l := range leaks {
		switch l.LeakType {
		case models.LeakTypeXSSSink:
			foundXSS = true
		case models.LeakTypeOpenRedirect:
			foundRedirect = true
		}
	}
	if !foundXSS {
		t.Error("expected XSS sink leak in JS content")
	}
	if foundRedirect {
		t.Error("expected no open redirect leak in input-to-innerHTML code")
	}
}

func TestAnalyzeFrontendSecurity_NoFrontendLeaksForAPI(t *testing.T) {
	var leaks []models.Leak
	var mu sync.Mutex

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("Access-Control-Allow-Origin", "https://specific-client.com")
	headers.Set("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
	headers.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; object-src 'none'")

	body := []byte(`{"status":"ok","data":{"id":1,"name":"test"}}`)

	analyzeFrontendSecurity("https://example.com/api/users", headers, body, &leaks, &mu)

	for _, l := range leaks {
		t.Errorf("unexpected leak for secure API response: %s: %s", l.LeakType, l.Snippet)
	}
}

func TestAnalyzeClientStorage_DetectsTokenInLocalStorage(t *testing.T) {
	var leaks []models.Leak
	body := `localStorage.setItem("accessToken", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGVzdA");`
	analyzeClientStorage(body, "https://example.com/app.js", &leaks)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeStorageLeak && l.SourceURL == "https://example.com/app.js" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected STORAGE_SENSITIVE_DATA leak for accessToken in localStorage")
	}
}

func TestAnalyzeClientStorage_DetectsTokenInSessionStorage(t *testing.T) {
	var leaks []models.Leak
	body := `sessionStorage.setItem("jwt", "header.payload.sig");`
	analyzeClientStorage(body, "https://example.com/app.js", &leaks)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeStorageLeak {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected STORAGE_SENSITIVE_DATA leak for jwt in sessionStorage")
	}
}

func TestAnalyzeClientStorage_DetectsAuthToken(t *testing.T) {
	var leaks []models.Leak
	body := `localStorage.setItem("auth_token", "some-secret-value");`
	analyzeClientStorage(body, "https://example.com/app.js", &leaks)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeStorageLeak {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected STORAGE_SENSITIVE_DATA leak for auth_token")
	}
}

func TestAnalyzeClientStorage_DetectsRefreshToken(t *testing.T) {
	var leaks []models.Leak
	body := `localStorage.setItem("refreshToken", "some-refresh-value");`
	analyzeClientStorage(body, "https://example.com/app.js", &leaks)

	found := false
	for _, l := range leaks {
		if l.LeakType == models.LeakTypeStorageLeak {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected STORAGE_SENSITIVE_DATA leak for refreshToken")
	}
}

func TestAnalyzeClientStorage_SkipsNonSensitiveKeys(t *testing.T) {
	var leaks []models.Leak
	body := `localStorage.setItem("theme", "dark");
localStorage.setItem("language", "en");
sessionStorage.setItem("cartItems", "3");`
	analyzeClientStorage(body, "https://example.com/app.js", &leaks)

	if len(leaks) > 0 {
		t.Fatalf("expected no leaks for benign keys, got %d", len(leaks))
	}
}

func TestAddStateMgr(t *testing.T) {
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	addStateMgr("Pinia", stateMgrSet, &mu)
	if _, ok := stateMgrSet["Pinia"]; !ok {
		t.Fatal("expected Pinia to be added")
	}

	addStateMgr("", stateMgrSet, &mu)
	if len(stateMgrSet) != 1 {
		t.Fatal("expected empty string to not add")
	}
}

func TestAddTechFromBody_DetectsPinia(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { defineStore } from "pinia";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Pinia"]; !ok {
		t.Fatal("expected Pinia state management detected")
	}
}

func TestAddTechFromBody_DetectsZustand(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { create } from "zustand";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Zustand"]; !ok {
		t.Fatal("expected Zustand state management detected")
	}
}

func TestAddTechFromBody_DetectsRedux(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { configureStore } from "@reduxjs/toolkit";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Redux"]; !ok {
		t.Fatal("expected Redux state management detected")
	}
}

func TestAddTechFromBody_DetectsVuex(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import Vue from "vue"; import Vuex from "vuex"; createStore({})`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Vuex"]; !ok {
		t.Fatal("expected Vuex state management detected")
	}
}

func TestAddTechFromBody_DetectsMobX(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { makeAutoObservable } from "mobx";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["MobX"]; !ok {
		t.Fatal("expected MobX state management detected")
	}
}

func TestAddTechFromBody_DetectsTanStackQuery(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { useQuery, QueryClient } from "@tanstack/react-query";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["TanStack Query / SWR"]; !ok {
		t.Fatal("expected TanStack Query / SWR state management detected")
	}
}

func TestAddTechFromBody_DetectsSWR(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import useSWR from "swr";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["TanStack Query / SWR"]; !ok {
		t.Fatal("expected TanStack Query / SWR state management detected")
	}
}

func TestAddTechFromBody_DetectsValtio(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { proxy } from "valtio";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Valtio/Effector"]; !ok {
		t.Fatal("expected Valtio/Effector state management detected")
	}
}

func TestAddTechFromBody_SkipsNonStateManagement(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`const x = 1; function hello() { return "world"; }`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if len(stateMgrSet) > 0 {
		t.Fatalf("expected no state management detected, got %d", len(stateMgrSet))
	}
}

func TestAddTechFromBody_DetectsEffector(t *testing.T) {
	techSet := make(map[string]struct{})
	stateMgrSet := make(map[string]struct{})
	var mu sync.Mutex

	body := []byte(`import { createStore, createEvent } from "effector";`)
	addTechFromBody("application/javascript", body, techSet, stateMgrSet, &mu)

	if _, ok := stateMgrSet["Valtio/Effector"]; !ok {
		t.Fatal("expected Valtio/Effector state management detected")
	}
}
