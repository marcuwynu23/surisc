package scanner

import (
	"net/url"
	"strings"
	"sync"
	"testing"

	"surisc/internal/models"
)

func TestAnalyzeContent_IgnoresRouteBasedPasswordAssignments(t *testing.T) {
	content := []byte(`
		const routes = {
			PASSWORD: "/auth/forgot-password",
			PASSWORD_RESET: "/auth/reset-password",
		};
	`)

	var leaks []models.Leak
	var mu sync.Mutex

	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	for _, leak := range leaks {
		if leak.LeakType == models.LeakTypeGenericSec {
			t.Fatalf("unexpected generic secret leak for route path: %q", leak.Snippet)
		}
	}
}

func TestAnalyzeContent_IgnoresBitcoinLikeHighEntropyStrings(t *testing.T) {
	content := []byte(`
		const wallets = [
			"19qfcMTGFlcK6Gl5h9PmlJd3DubeFdiOz",
			"1BbiTxGrWqiEevyxGLX1Ypyto4eA1hSz2",
			"1EdaeVAqCskmS2ypgjIvQ1YR5NfKG7eO3",
		];
	`)

	var leaks []models.Leak
	var mu sync.Mutex

	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	for _, leak := range leaks {
		if leak.LeakType == models.LeakTypeHighEntropy {
			t.Fatalf("unexpected high entropy leak for public address-like string: %q", leak.Snippet)
		}
	}
}

func TestAnalyzeContent_DedupesRepeatedInternalIPs(t *testing.T) {
	content := []byte(`
		const ips = ["192.168.1.182", "192.168.1.182", "192.168.1.182"];
	`)

	var leaks []models.Leak
	var mu sync.Mutex

	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	var internalIPCount int
	for _, leak := range leaks {
		if leak.LeakType == models.LeakTypeInternalIP && leak.Snippet == "192.168.1.182" {
			internalIPCount++
		}
	}
	if internalIPCount != 1 {
		t.Fatalf("expected one deduped internal IP finding, got %d", internalIPCount)
	}
}

func TestAnalyzeContent_IgnoresPlaceholderSecretValues(t *testing.T) {
	content := []byte(`
		const a = { password: "your-email-password" };
		const b = "YOUR_CLIENT_SECRET";
		const c = "YOUR_CONSUMER_SECRET";
	`)

	var leaks []models.Leak
	var mu sync.Mutex

	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	for _, leak := range leaks {
		if leak.LeakType != models.LeakTypeGenericSec {
			continue
		}
		s := leak.Snippet
		if strings.Contains(strings.ToLower(s), "your-email-password") ||
			strings.Contains(strings.ToLower(s), "your_client_secret") ||
			strings.Contains(strings.ToLower(s), "your_consumer_secret") {
			t.Fatalf("unexpected placeholder generic secret leak: %q", leak.Snippet)
		}
	}
}

func TestAnalyzeContent_DoesNotFlagRSAHeaderWithoutKeyBody(t *testing.T) {
	content := []byte(`const marker = "-----BEGIN RSA PRIVATE KEY-----";`)

	var leaks []models.Leak
	var mu sync.Mutex

	analyzeContent("https://example.com/assets/index.js", content, &leaks, &mu)

	for _, leak := range leaks {
		if leak.LeakType == models.LeakTypeRSAPrivate {
			t.Fatalf("unexpected rsa key finding for marker-only content: %q", leak.Snippet)
		}
	}
}

func TestExtractRoutesFromContent_IgnoresMarkdownFencedCodeBlocks(t *testing.T) {
	content := []byte(`
outside route "/public/docs"

` + "```bash" + `
curl https://example.com/api/private
cat /etc/nginx/sites-available
echo "/admin"
` + "```" + `

outside absolute https://example.com/health
`)

	baseURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("failed to parse base url: %v", err)
	}

	routeSet := make(map[string]struct{})
	var mu sync.Mutex
	extractRoutesFromContent(content, baseURL, routeSet, &mu)

	if _, ok := routeSet["/public/docs"]; !ok {
		t.Fatalf("expected outside route to be kept, got %v", routeSet)
	}
	if _, ok := routeSet["/health"]; !ok {
		t.Fatalf("expected outside absolute route to be kept, got %v", routeSet)
	}
	if _, ok := routeSet["/admin"]; ok {
		t.Fatalf("expected fenced code route to be ignored, got %v", routeSet)
	}
	if _, ok := routeSet["/api/private"]; ok {
		t.Fatalf("expected fenced absolute route to be ignored, got %v", routeSet)
	}
}
