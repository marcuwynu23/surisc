package tests

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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
		case "/admin":
			http.SetCookie(w, &http.Cookie{
				Name:     "auth_token",
				Value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "ok")
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `import React from "react"; import { createApp } from "vue"; console.log("solid-js"); window.Shopify = { shop: "demo.myshopify.com" };`)
		case "/api", "/auth", "/dashboard", "/graphql", "/__surisc_nonexistent_route_probe__":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>spa fallback</body></html>")
		case "/robots.txt":
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nAllow: /\nDisallow: /admin\nSitemap: "+ts.URL+"/sitemap.xml\n")
		case "/sitemap.xml":
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<urlset><url><loc>%s/about</loc></url><url><loc>%s/docs/getting-started</loc></url></urlset>`, ts.URL, ts.URL)
		default:
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `
				<html>
					<head>
						<link rel="manifest" href="/manifest.webmanifest" />
					</head>
					<body>
						<div id="root"></div>
						<script type="module" src="/@vite/client"></script>
						<a href="/about">About</a>
						<a href="/docs/getting-started">Docs</a>
						<form action="/auth/login"></form>
						<script src="/registerSW.js"></script>
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
		"/manifest.webmanifest",
		"/registerSW.js",
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
	if insight.PWA == "" || insight.PWA == "No" {
		t.Fatalf("expected PWA to be detected, got %q", insight.PWA)
	}
	if insight.Frontend == "" || !strings.Contains(insight.Frontend, "Vite") || !strings.Contains(insight.Frontend, "React") || !strings.Contains(insight.Frontend, "Shopify") {
		t.Fatalf("expected frontend summary to include Vite and React, got %q", insight.Frontend)
	}
	if insight.ContentSecurityPolicy == "" {
		t.Fatalf("expected Content-Security-Policy to be detected")
	}
	if insight.XFrameOptions == "" {
		t.Fatalf("expected X-Frame-Options to be detected")
	}
	if insight.StrictTransportSecurity == "" {
		t.Fatalf("expected Strict-Transport-Security to be detected")
	}
	if insight.AccessControlAllowOrigin == "" {
		t.Fatalf("expected Access-Control-Allow-Origin to be detected")
	}
	if len(insight.CookieSecurity) == 0 {
		t.Fatalf("expected cookie security findings")
	}
	if len(insight.JWTIndicators) == 0 {
		t.Fatalf("expected jwt indicators")
	}
	if len(insight.ProbedRoutes) != 1 || insight.ProbedRoutes[0] != "/admin -> 200" {
		t.Fatalf("expected only real attack-surface route to remain, got %v", insight.ProbedRoutes)
	}
}

func TestRunScanInformativeSkipsDataScriptSrc(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nAllow: /\n")
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script src="data:text/javascript;base64,Zm9v"></script></body></html>`)
		}
	}))
	defer ts.Close()

	var logs bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(origOut)

	_, _ = scanner.RunScan(ts.URL, true)

	if strings.Contains(logs.String(), `unsupported protocol scheme "data"`) {
		t.Fatalf("expected data: script sources to be skipped, got logs: %s", logs.String())
	}
}

func TestRunScanInformativeDetectsHostingProviderVercel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Vercel-Id", "sin1::abc123")
		w.Header().Set("Server", "Vercel")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Vercel" {
		t.Fatalf("expected hosting provider Vercel, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeDetectsHostingProviderHeroku(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 vegur")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Heroku" {
		t.Fatalf("expected hosting provider Heroku, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeDetectsHostingProviderRailway(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Railway-Request-Id", "req_123")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Railway" {
		t.Fatalf("expected hosting provider Railway, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeDetectsCloudflareProxiedHosting(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123-SIN")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Cloudflare Proxied" {
		t.Fatalf("expected cloudflare proxied hosting label, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeDetectsCloudflarePagesByCodeSignal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123-SIN")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><meta name="generator" content="Cloudflare Pages"></head><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Cloudflare Pages" {
		t.Fatalf("expected Cloudflare Pages from code signal, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeDetectsCloudflarePagesByHeaderPattern(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "9ed2708adfb62ae3-LAX")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
		w.Header().Set("Speculation-Rules", `"/cdn-cgi/speculation"`)
		w.Header().Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Cloudflare Pages" {
		t.Fatalf("expected Cloudflare Pages from header pattern, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeKeepsCloudflareProxiedWhenOriginFingerprintPresent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "9ed271270dd1f7e3-LAX")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.Header().Set("X-Drupal-Cache", "MISS")
		w.Header().Set("X-Generator", "Drupal 7 (http://drupal.org)")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.Hosting != "Cloudflare Proxied" {
		t.Fatalf("expected Cloudflare Proxied with origin fingerprint, got %q", insight.Hosting)
	}
}

func TestRunScanInformativeIgnoresHTMLFallbackForRobotsAndSitemap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt", "/sitemap.xml":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><body>fallback</body></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
		}
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.RobotsTxt != "" {
		t.Fatalf("expected robots.txt HTML fallback to be ignored")
	}
	if insight.SitemapXML != "" {
		t.Fatalf("expected sitemap.xml HTML fallback to be ignored")
	}
}

func TestRunScanInformativeIgnoresMixedRobotsWithHTML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nAllow: /\n\n<!doctype html><html><body>fallback</body></html>")
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><div id="root"></div></body></html>`)
		}
	}))
	defer ts.Close()

	_, insight := scanner.RunScan(ts.URL, true)
	if insight.RobotsTxt != "" {
		t.Fatalf("expected robots.txt mixed HTML content to be ignored")
	}
}
