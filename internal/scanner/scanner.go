package scanner

import (
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	colly "github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"surisc/internal/models"
)

var (
	// Regex Patterns
	rxGoogleKey        = regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`)
	rxAWSKey           = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	rxStripeKey        = regexp.MustCompile(`[rs]k_live_[0-9a-zA-Z]{24,}`)
	rxGitHubToken      = regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)
	rxSlackToken       = regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`)
	rxGitLabToken      = regexp.MustCompile(`glpat-[0-9a-zA-Z\-]{20}`)
	rxSendGridKey      = regexp.MustCompile(`SG\.[a-zA-Z0-9_\-\.]{43,}`)
	rxMailgunKey       = regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)
	rxResendKey        = regexp.MustCompile(`re_[a-zA-Z0-9]{24}`)
	rxTwilioKey        = regexp.MustCompile(`(?:SK|AC)[a-z0-9]{32}`)
	rxSquareToken      = regexp.MustCompile(`sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`)
	rxCloudflareGlobal = regexp.MustCompile(`(?i)(?:cloudflare|cf)[^\n]{0,80}(?:global(?:_|[\s-])?api(?:_|[\s-])?key|api(?:_|[\s-])?key)[^\n]{0,20}["']([0-9a-f]{37})["']`)
	rxCloudflareToken  = regexp.MustCompile(`(?is)(?:cloudflare|cf)[\s\S]{0,80}(?:api(?:_|[\s-])?token|token)[\s"'=:]{0,20}([A-Za-z0-9\-_]{20,})`)
	rxUserAPIToken     = regexp.MustCompile(`(?i)(?:user(?:_|[\s-])?api(?:_|[\s-])?token|api(?:_|[\s-])?token(?:_|[\s-])?user)[a-z0-9_]*["']?\s*[:=]\s*["']([A-Za-z0-9\-_]{16,})["']`)
	rxRSAPrivate       = regexp.MustCompile(`(?s)-----BEGIN (?:RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----[\s\S]{32,}?-----END (?:RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`)
	rxMapFile          = regexp.MustCompile(`sourceMappingURL=.*\.map`)
	rxBearerToken      = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`)
	rxInternalIP       = regexp.MustCompile(`(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`)
	rxImportMeta       = regexp.MustCompile(`import\.meta\.[A-Za-z0-9_\.]+`)
	rxSecretAssignment = regexp.MustCompile(`(?i)(?:api_?key|apikey|secret|token|password)[a-z0-9_]*["']?\s*[:=]\s*["']([A-Za-z0-9\-_=+\/]{12,})["']`)
	rxSecretString     = regexp.MustCompile(`(?i)["'][a-z0-9_]*(?:api_?key|apikey|secret|token|password)[a-z0-9_]*["']`)
	rxPotentialSecret  = regexp.MustCompile(`["'][A-Za-z0-9/+=]{20,}["']`)
	rxBTCAddress       = regexp.MustCompile(`^(?:[13])[a-km-zA-HJ-NP-Z1-9]{25,34}$`)
	rxRouteLiteral     = regexp.MustCompile(`["'](\/[A-Za-z0-9._~!$&()*+,;=:@%\-\/]*)["']`)
	rxAbsoluteURL      = regexp.MustCompile(`https?://[A-Za-z0-9\.\-]+(?:\:[0-9]+)?\/[A-Za-z0-9._~!$&()*+,;=:@%\-\/]*`)
	rxJWTLike          = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$`)
	rxWhitespace       = regexp.MustCompile(`\s+`)
)

func RunScan(targetURL string, informativeOnly bool) ([]models.Leak, models.TechInsight) {
	c := colly.NewCollector(
		colly.Async(true),
	)

	// Apply browser-like evasion techniques
	extensions.RandomUserAgent(c)
	extensions.Referer(c)

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		r.Headers.Set("Accept-Language", "en-US,en;q=0.9")
		r.Headers.Set("Cache-Control", "max-age=0")
		r.Headers.Set("Connection", "keep-alive")
		r.Headers.Set("Upgrade-Insecure-Requests", "1")
	})

	var leaks []models.Leak
	var insight models.TechInsight
	var leaksMutex sync.Mutex
	var insightMutex sync.Mutex
	var routesMutex sync.Mutex
	routeSet := make(map[string]struct{})
	baseTarget := mustParseURL(targetURL)
	var wg sync.WaitGroup

	err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 5,               // Reduced to mimic realistic human traffic
		RandomDelay: 2 * time.Second, // Delay between requests
	})
	if err != nil {
		log.Fatalf("Failed to set limit rule: %v", err)
	}

	// Capture HTTP Protocol (HTTP/1.1, HTTP/2.0)
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, err := http.NewRequest("HEAD", targetURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0")
			client := &http.Client{Timeout: 5 * time.Second}
			if resp, err := client.Do(req); err == nil {
				insightMutex.Lock()
				insight.Protocol = resp.Proto
				if insight.ContentSecurityPolicy == "" {
					insight.ContentSecurityPolicy = resp.Header.Get("Content-Security-Policy")
				}
				if insight.XFrameOptions == "" {
					insight.XFrameOptions = resp.Header.Get("X-Frame-Options")
				}
				if insight.StrictTransportSecurity == "" {
					insight.StrictTransportSecurity = resp.Header.Get("Strict-Transport-Security")
				}
				if insight.AccessControlAllowOrigin == "" {
					insight.AccessControlAllowOrigin = resp.Header.Get("Access-Control-Allow-Origin")
				}
				mergeCookieInsights(resp.Cookies(), &insight)
				insightMutex.Unlock()
			}
		}
	}()

	if informativeOnly {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if body, ok := fetchOptionalRobots(targetURL); ok {
				insightMutex.Lock()
				insight.RobotsTxt = body
				insightMutex.Unlock()
				extractRoutesFromContent([]byte(body), mustParseURL(targetURL), routeSet, &routesMutex)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if body, ok := fetchOptionalSitemap(targetURL); ok {
				insightMutex.Lock()
				insight.SitemapXML = body
				insightMutex.Unlock()
				extractRoutesFromContent([]byte(body), mustParseURL(targetURL), routeSet, &routesMutex)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			probe := probeAttackSurfaceRoutes(targetURL, []string{"/admin", "/api", "/auth", "/dashboard", "/graphql"})
			insightMutex.Lock()
			insight.ProbedRoutes = probe.routes
			for _, c := range probe.cookies {
				insight.CookieSecurity = append(insight.CookieSecurity, c)
			}
			for _, j := range probe.jwtIndicators {
				insight.JWTIndicators = append(insight.JWTIndicators, j)
			}
			insightMutex.Unlock()
			for _, p := range probe.existingPaths {
				addRoute(p, mustParseURL(targetURL), routeSet, &routesMutex)
			}
		}()
	}

	// Technical Insights: CMS and Frontend Check
	c.OnHTML("meta[name=generator]", func(e *colly.HTMLElement) {
		insightMutex.Lock()
		defer insightMutex.Unlock()
		insight.CMS = e.Attr("content")
	})

	c.OnHTML("div[id=__next]", func(e *colly.HTMLElement) {
		insightMutex.Lock()
		defer insightMutex.Unlock()
		insight.Frontend = "React (Next.js)"
		insight.SPA = "Yes"
	})

	c.OnHTML("div[id=root], div[id=app], script[type=module]", func(e *colly.HTMLElement) {
		insightMutex.Lock()
		defer insightMutex.Unlock()
		if insight.SPA == "" {
			insight.SPA = "Likely"
		}
	})

	// Collect route hints from common HTML attributes.
	c.OnHTML("a[href], link[href], script[src], img[src], form[action]", func(e *colly.HTMLElement) {
		var ref string
		switch {
		case e.Attr("href") != "":
			ref = e.Attr("href")
		case e.Attr("src") != "":
			ref = e.Attr("src")
		default:
			ref = e.Attr("action")
		}
		if ref == "" {
			return
		}
		addRoute(ref, e.Request.URL, routeSet, &routesMutex)
	})

	// Intercept inline scripts and <script src="...">
	c.OnHTML("script", func(e *colly.HTMLElement) {
		src := e.Attr("src")

		// Tech Insights from script paths
		if src != "" {
			insightMutex.Lock()
			if strings.Contains(src, "/_next/") {
				insight.Frontend = "React (Next.js)"
				insight.SPA = "Yes"
			} else if strings.Contains(src, "/_nuxt/") {
				insight.Frontend = "Vue.js (Nuxt)"
				insight.SPA = "Yes"
			} else if strings.Contains(src, "wp-includes") || strings.Contains(src, "wp-content") {
				insight.CMS = "WordPress"
				insight.Backend = "PHP (WordPress)"
			}
			insightMutex.Unlock()
		}

		if src == "" && !informativeOnly {
			// Inline script
			content := e.Text
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzeContent(e.Request.URL.String(), []byte(content), &leaks, &leaksMutex)
			}()
		} else if src != "" && !informativeOnly {
			// External script
			absURL := e.Request.AbsoluteURL(src)
			if absURL != "" {
				e.Request.Visit(absURL)
			}
		}
	})

	// Process JS responses and global headers
	c.OnResponse(func(r *colly.Response) {
		// Tech Insights from Headers
		insightMutex.Lock()
		if insight.Server == "" && r.Headers.Get("Server") != "" {
			insight.Server = r.Headers.Get("Server")
		}
		if insight.Backend == "" {
			if powered := r.Headers.Get("X-Powered-By"); powered != "" {
				insight.Backend = powered
			}
		}
		if insight.CDNWAF == "" {
			if r.Headers.Get("CF-Ray") != "" {
				insight.CDNWAF = "Cloudflare"
			} else if via := r.Headers.Get("Via"); via != "" {
				insight.CDNWAF = "Via: " + via
			}
		}
		if insight.ContentSecurityPolicy == "" {
			insight.ContentSecurityPolicy = r.Headers.Get("Content-Security-Policy")
		}
		if insight.XFrameOptions == "" {
			insight.XFrameOptions = r.Headers.Get("X-Frame-Options")
		}
		if insight.StrictTransportSecurity == "" {
			insight.StrictTransportSecurity = r.Headers.Get("Strict-Transport-Security")
		}
		if insight.AccessControlAllowOrigin == "" {
			insight.AccessControlAllowOrigin = r.Headers.Get("Access-Control-Allow-Origin")
		}
		mergeCookieInsights(cookiesFromHeader(r.Headers), &insight)
		insightMutex.Unlock()

		ctype := r.Headers.Get("Content-Type")
		if strings.Contains(ctype, "text/html") && baseTarget != nil && r.Request.URL != nil && r.Request.URL.Host == baseTarget.Host {
			classification := classifySPAFromHTML(r.Body)
			if classification != "" {
				insightMutex.Lock()
				if insight.SPA == "" || insight.SPA == "No" {
					insight.SPA = classification
				}
				insightMutex.Unlock()
			}
		}
		if strings.Contains(ctype, "javascript") || strings.Contains(ctype, "json") || strings.Contains(ctype, "text/html") || strings.HasSuffix(r.Request.URL.Path, ".js") {
			extractRoutesFromContent(r.Body, r.Request.URL, routeSet, &routesMutex)
		}
		if !informativeOnly && (strings.Contains(ctype, "javascript") || strings.Contains(ctype, "json") || strings.HasSuffix(r.Request.URL.Path, ".js")) {
			content := make([]byte, len(r.Body))
			copy(content, r.Body) // Copy to isolate from colly internal buffers
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzeContent(r.Request.URL.String(), content, &leaks, &leaksMutex)
			}()
		}
	})

	// Setup error handling
	c.OnError(func(r *colly.Response, err error) {
		log.Printf("Error scraping %s: %s\n", r.Request.URL, err)
	})

	c.Visit(targetURL)
	c.Wait()
	wg.Wait()
	if insight.SPA == "" {
		insight.SPA = "No"
	}
	sort.Strings(insight.CookieSecurity)
	sort.Strings(insight.JWTIndicators)
	insight.Routes = sortedRoutes(routeSet)

	return leaks, insight
}

func mergeCookieInsights(cookies []*http.Cookie, insight *models.TechInsight) {
	cookieSet := make(map[string]struct{}, len(insight.CookieSecurity))
	jwtSet := make(map[string]struct{}, len(insight.JWTIndicators))
	for _, v := range insight.CookieSecurity {
		cookieSet[v] = struct{}{}
	}
	for _, v := range insight.JWTIndicators {
		jwtSet[v] = struct{}{}
	}

	for _, c := range cookies {
		if c == nil {
			continue
		}
		if c.HttpOnly {
			cookieSet["HttpOnly cookie: "+c.Name] = struct{}{}
		}
		if c.Secure {
			cookieSet["Secure cookie: "+c.Name] = struct{}{}
		}
		if c.SameSite != http.SameSiteDefaultMode {
			cookieSet["SameSite cookie: "+c.Name] = struct{}{}
		}
		nameLower := strings.ToLower(c.Name)
		if strings.Contains(nameLower, "jwt") || strings.Contains(nameLower, "token") || strings.Contains(nameLower, "auth") {
			jwtSet["JWT-like cookie name: "+c.Name] = struct{}{}
		}
		if rxJWTLike.MatchString(c.Value) {
			jwtSet["JWT-like cookie value: " + c.Name] = struct{}{}
		}
	}

	insight.CookieSecurity = mapKeys(cookieSet)
	insight.JWTIndicators = mapKeys(jwtSet)
}

func mapKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type attackSurfaceProbeResult struct {
	routes        []string
	existingPaths []string
	cookies       []string
	jwtIndicators []string
}

func probeAttackSurfaceRoutes(base string, paths []string) attackSurfaceProbeResult {
	baseURL, err := url.Parse(base)
	if err != nil {
		return attackSurfaceProbeResult{}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	results := make([]string, 0, len(paths))
	existingPaths := make([]string, 0, len(paths))
	var insight models.TechInsight
	homeCT, homeBody, _, _ := fetchRouteResponse(client, baseURL, "/")
	homeNormSig := normalizedResponseSignature(homeCT, homeBody, paths)
	fallbackCT, fallbackBody, _, _ := fetchRouteResponse(client, baseURL, "/__surisc_nonexistent_route_probe__")
	fallbackNormSig := normalizedResponseSignature(fallbackCT, fallbackBody, paths)

	for _, p := range paths {
		ctype, body, statusCode, cookies := fetchRouteResponse(client, baseURL, p)
		if statusCode == 0 {
			results = append(results, fmt.Sprintf("%s -> request error", p))
			continue
		}
		mergeCookieInsights(cookies, &insight)
		if statusCode < 400 {
			normalizedSig := normalizedResponseSignature(ctype, body, paths)
			if isLikelyFallbackResponse(ctype, normalizedSig, homeNormSig, fallbackNormSig) {
				continue
			}
			// Be conservative: 200 HTML on probed admin/api/auth paths is often SPA fallback.
			// Only keep 200 responses when they are non-HTML and more likely endpoint-specific.
			if statusCode == 200 && strings.Contains(strings.ToLower(ctype), "html") {
				continue
			}
			results = append(results, fmt.Sprintf("%s -> %d", p, statusCode))
			existingPaths = append(existingPaths, p)
		}
	}
	sort.Strings(results)
	sort.Strings(existingPaths)
	return attackSurfaceProbeResult{
		routes:        results,
		existingPaths: existingPaths,
		cookies:       insight.CookieSecurity,
		jwtIndicators: insight.JWTIndicators,
	}
}

func fetchRouteResponse(client *http.Client, baseURL *url.URL, path string) (string, []byte, int, []*http.Cookie) {
	ref, err := url.Parse(path)
	if err != nil {
		return "", nil, 0, nil
	}
	u := baseURL.ResolveReference(ref).String()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", nil, 0, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.Header.Get("Content-Type"), body, resp.StatusCode, resp.Cookies()
}

func responseSignature(contentType string, body []byte) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(contentType)))
	_, _ = h.Write(body)
	return fmt.Sprintf("%x", h.Sum64())
}

func normalizedResponseSignature(contentType string, body []byte, probePaths []string) string {
	normalized := normalizeBodyForComparison(string(body), probePaths)
	return responseSignature(strings.ToLower(contentType), []byte(normalized))
}

func normalizeBodyForComparison(body string, probePaths []string) string {
	s := strings.ToLower(body)
	s = rxAbsoluteURL.ReplaceAllString(s, "")
	for _, p := range probePaths {
		s = strings.ReplaceAll(s, strings.ToLower(p), "")
	}
	s = rxWhitespace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func isLikelyFallbackResponse(contentType, sig, homeSig, missingSig string) bool {
	ct := strings.ToLower(contentType)
	if !strings.Contains(ct, "html") {
		return false
	}
	if sig == "" {
		return false
	}
	if homeSig != "" && sig == homeSig {
		return true
	}
	if missingSig != "" && sig == missingSig {
		return true
	}
	return false
}

func cookiesFromHeader(h *http.Header) []*http.Cookie {
	if h == nil {
		return nil
	}
	resp := &http.Response{Header: *h}
	return resp.Cookies()
}

func classifySPAFromHTML(body []byte) string {
	html := strings.ToLower(string(body))
	positiveSignals := []string{
		`id="__next"`,
		`id='__next'`,
		`id="root"`,
		`id='root'`,
		`id="app"`,
		`id='app'`,
		`<script type="module"`,
		`<script type='module'`,
	}
	for _, signal := range positiveSignals {
		if strings.Contains(html, signal) {
			return "Likely"
		}
	}
	return "No"
}

func analyzeContent(sourceURL string, content []byte, leaks *[]models.Leak, mutex *sync.Mutex) {
	var localLeaks []models.Leak

	// 1. Google API Key
	if matches := rxGoogleKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeGoogleKey,
				SourceURL:    sourceURL,
				GravityScore: 9.0,
				Snippet:      string(m),
			})
		}
	}

	// 1.1 AWS Access Keys
	if matches := rxAWSKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeAWSKey,
				SourceURL:    sourceURL,
				GravityScore: 10.0,
				Snippet:      string(m),
			})
		}
	}

	// 1.2 Stripe Secret Keys
	if matches := rxStripeKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeStripeKey,
				SourceURL:    sourceURL,
				GravityScore: 10.0,
				Snippet:      string(m),
			})
		}
	}

	// 1.3 GitHub PATs
	if matches := rxGitHubToken.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeGitHubToken,
				SourceURL:    sourceURL,
				GravityScore: 10.0,
				Snippet:      string(m),
			})
		}
	}

	// 1.4 Slack Tokens
	if matches := rxSlackToken.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeSlackToken,
				SourceURL:    sourceURL,
				GravityScore: 9.5,
				Snippet:      string(m),
			})
		}
	}

	// 1.5 GitLab PATs
	if matches := rxGitLabToken.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeGitLabToken,
				SourceURL:    sourceURL,
				GravityScore: 10.0,
				Snippet:      string(m),
			})
		}
	}

	// 1.6 SendGrid, Mailgun, Resend, Twilio, Square
	if matches := rxSendGridKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{LeakType: models.LeakTypeSendGridKey, SourceURL: sourceURL, GravityScore: 10.0, Snippet: string(m)})
		}
	}
	if matches := rxMailgunKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{LeakType: models.LeakTypeMailgunKey, SourceURL: sourceURL, GravityScore: 10.0, Snippet: string(m)})
		}
	}
	if matches := rxResendKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{LeakType: models.LeakTypeResendKey, SourceURL: sourceURL, GravityScore: 10.0, Snippet: string(m)})
		}
	}
	if matches := rxTwilioKey.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{LeakType: models.LeakTypeTwilioKey, SourceURL: sourceURL, GravityScore: 9.5, Snippet: string(m)})
		}
	}
	if matches := rxSquareToken.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{LeakType: models.LeakTypeSquareToken, SourceURL: sourceURL, GravityScore: 10.0, Snippet: string(m)})
		}
	}

	// 1.7 Cloudflare exposed credentials (global key / API token)
	if matches := rxCloudflareGlobal.FindAllSubmatch(content, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				localLeaks = append(localLeaks, models.Leak{
					LeakType:     models.LeakTypeCloudflare,
					SourceURL:    sourceURL,
					GravityScore: 10.0,
					Snippet:      truncate(string(m[1]), 50),
				})
			}
		}
	}
	if matches := rxCloudflareToken.FindAllSubmatch(content, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				token := string(m[1])
				if shannonEntropy(token) > 3.2 {
					localLeaks = append(localLeaks, models.Leak{
						LeakType:     models.LeakTypeCloudflare,
						SourceURL:    sourceURL,
						GravityScore: 9.5,
						Snippet:      truncate(token, 50),
					})
				}
			}
		}
	}

	// 1.8 User API token assignments
	if matches := rxUserAPIToken.FindAllSubmatch(content, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				token := string(m[1])
				tokenLower := strings.ToLower(token)
				if shannonEntropy(token) > 3.0 && !isLikelyPlaceholderValue(tokenLower) {
					localLeaks = append(localLeaks, models.Leak{
						LeakType:     models.LeakTypeUserAPIToken,
						SourceURL:    sourceURL,
						GravityScore: 8.8,
						Snippet:      truncate(token, 50),
					})
				}
			}
		}
	}

	// 1.9 RSA Private Keys
	if matches := rxRSAPrivate.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeRSAPrivate,
				SourceURL:    sourceURL,
				GravityScore: 10.0,
				Snippet:      string(m),
			})
		}
	}

	// 2. Map File References
	if matches := rxMapFile.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeMapFile,
				SourceURL:    sourceURL,
				GravityScore: 5.0,
				Snippet:      string(m),
			})
		}
	}

	// 3. Bearer Tokens
	if matches := rxBearerToken.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			token := string(m)
			ent := shannonEntropy(token)
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeBearerToken,
				SourceURL:    sourceURL,
				GravityScore: 7.0 + (ent * 0.5),
				Snippet:      truncate(token, 50),
			})
		}
	}

	// 4. Internal IP Addresses
	if matches := rxInternalIP.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeInternalIP,
				SourceURL:    sourceURL,
				GravityScore: 6.5,
				Snippet:      string(m),
			})
		}
	}

	// 5. Import Meta Leaks
	if matches := rxImportMeta.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			s := string(m)
			// Ignore standard non-sensitive references
			if s == "import.meta.url" || s == "import.meta.hot" || s == "import.meta.env" {
				continue
			}
			localLeaks = append(localLeaks, models.Leak{
				LeakType:     models.LeakTypeImportMeta,
				SourceURL:    sourceURL,
				GravityScore: 8.5,
				Snippet:      s,
			})
		}
	}

	// 6. Shannon Entropy for High-Density Secrets
	if potentialSecrets := rxPotentialSecret.FindAll(content, -1); potentialSecrets != nil {
		for _, bSecret := range potentialSecrets {
			secret := string(bSecret)
			if len(secret) >= 2 {
				secret = secret[1 : len(secret)-1] // strip quotes
			}

			if len(secret) > 20 && !strings.HasPrefix(secret, "AGFzbQE") && !strings.HasPrefix(secret, "AIza") && !strings.Contains(secret, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") && !isLikelyNonSecretHighEntropy(secret) {
				ent := shannonEntropy(secret)
				if ent > 4.5 {
					localLeaks = append(localLeaks, models.Leak{
						LeakType:     models.LeakTypeHighEntropy,
						SourceURL:    sourceURL,
						GravityScore: ent * 2.0,
						Snippet:      truncate(secret, 50),
					})
				}
			}
		}
	}

	// 7. Generic Secret Assignments (var apiKey = "XYZ")
	if matches := rxSecretAssignment.FindAllSubmatch(content, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 {
				val := string(m[1])
				valLower := strings.ToLower(val)
				// Filter known placeholders and require minimum entropy for the value
				if shannonEntropy(val) > 3.0 && !isLikelyPlaceholderValue(valLower) && !isLikelyRouteValue(val) {
					localLeaks = append(localLeaks, models.Leak{
						LeakType:     models.LeakTypeGenericSec,
						SourceURL:    sourceURL,
						GravityScore: 8.0,
						Snippet:      truncate(string(m[0]), 100),
					})
				}
			}
		}
	}

	// 8. Long Hardcoded Secret Strings
	if matches := rxSecretString.FindAll(content, -1); matches != nil {
		for _, m := range matches {
			s := string(m)
			if len(s) >= 20 { // Discards random short words like "password"
				// Ignore explicit React frontend library internals
				if strings.Contains(s, "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED") {
					continue
				}

				if isLikelyPlaceholderValue(strings.ToLower(s)) {
					continue
				}

				// Should have very high entropy, or be a massive uppercase warning string
				if shannonEntropy(s) > 4.0 || (strings.ToUpper(s) == s && strings.Contains(s, "SECRET")) {
					localLeaks = append(localLeaks, models.Leak{
						LeakType:     models.LeakTypeGenericSec,
						SourceURL:    sourceURL,
						GravityScore: 8.0,
						Snippet:      truncate(s, 100),
					})
				}
			}
		}
	}

	if len(localLeaks) > 0 {
		localLeaks = dedupeLeaks(localLeaks)
		mutex.Lock()
		*leaks = append(*leaks, localLeaks...)
		mutex.Unlock()
	}
}

// shannonEntropy calculates the Shannon entropy of a string
// representing its information density.
func shannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	frequencies := make(map[rune]float64)
	for _, char := range data {
		frequencies[char]++
	}

	var entropy float64
	length := float64(len(data))
	for _, count := range frequencies {
		freq := count / length
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}

func truncate(s string, l int) string {
	if len(s) > l {
		return s[:l] + "..."
	}
	return s
}

// isLikelyRouteValue suppresses path-like values from generic secret assignments.
func isLikelyRouteValue(val string) bool {
	v := strings.TrimSpace(strings.ToLower(val))
	if strings.HasPrefix(v, "/") {
		return true
	}
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return true
	}
	if strings.Contains(v, "/auth/") || strings.Contains(v, "/api/") {
		return true
	}
	return false
}

func isLikelyPlaceholderValue(v string) bool {
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(v)
	return strings.Contains(normalized, "your_") ||
		strings.Contains(normalized, "example") ||
		strings.Contains(normalized, "sample") ||
		strings.Contains(normalized, "dummy") ||
		strings.Contains(normalized, "test_") ||
		strings.Contains(normalized, "changeme")
}

// isLikelyNonSecretHighEntropy filters common high-entropy but non-secret literals.
func isLikelyNonSecretHighEntropy(secret string) bool {
	// Legacy Base58 Bitcoin addresses are high entropy but public by design.
	if rxBTCAddress.MatchString(secret) {
		return true
	}
	// Minified frontend bundles often contain opaque identifiers that are alnum-only.
	// If it is strictly alphanumeric and begins with a digit, treat as likely ID.
	if len(secret) >= 24 && len(secret) <= 40 && strings.HasPrefix(secret, "1") {
		isAlphaNum := true
		for _, ch := range secret {
			if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
				isAlphaNum = false
				break
			}
		}
		if isAlphaNum {
			return true
		}
	}
	return false
}

func dedupeLeaks(in []models.Leak) []models.Leak {
	seen := make(map[string]struct{}, len(in))
	out := make([]models.Leak, 0, len(in))
	for _, leak := range in {
		key := string(leak.LeakType) + "|" + leak.SourceURL + "|" + leak.Snippet
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, leak)
	}
	return out
}

func extractRoutesFromContent(content []byte, baseURL *url.URL, routeSet map[string]struct{}, mu *sync.Mutex) {
	matches := rxRouteLiteral.FindAllSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		addRoute(string(m[1]), baseURL, routeSet, mu)
	}

	absMatches := rxAbsoluteURL.FindAll(content, -1)
	for _, m := range absMatches {
		addRoute(string(m), baseURL, routeSet, mu)
	}
}

func addRoute(raw string, baseURL *url.URL, routeSet map[string]struct{}, mu *sync.Mutex) {
	clean := strings.TrimSpace(raw)
	if clean == "" || strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, "data:") || strings.HasPrefix(clean, "javascript:") {
		return
	}

	refURL, err := url.Parse(clean)
	if err != nil {
		return
	}
	if baseURL == nil {
		return
	}
	abs := baseURL.ResolveReference(refURL)
	if abs.Host != baseURL.Host || abs.Path == "" || abs.Path == "/" {
		return
	}

	normalized := abs.Path
	if abs.RawQuery != "" {
		normalized += "?" + abs.RawQuery
	}

	mu.Lock()
	routeSet[normalized] = struct{}{}
	mu.Unlock()
}

func sortedRoutes(routeSet map[string]struct{}) []string {
	if len(routeSet) == 0 {
		return nil
	}
	out := make([]string, 0, len(routeSet))
	for r := range routeSet {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func fetchOptionalText(base, p string) (string, bool) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(p)
	if err != nil {
		return "", false
	}

	u := baseURL.ResolveReference(ref).String()
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024))
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "", false
	}
	return s, true
}

func fetchOptionalRobots(base string) (string, bool) {
	text, ctype, ok := fetchOptionalWithType(base, "/robots.txt")
	if !ok {
		return "", false
	}
	bodyLower := strings.ToLower(strings.TrimSpace(text))
	typeLower := strings.ToLower(ctype)

	// Reject common SPA/HTML fallbacks.
	if strings.Contains(typeLower, "text/html") ||
		strings.Contains(bodyLower, "<!doctype html") ||
		strings.Contains(bodyLower, "<html") {
		return "", false
	}
	// Prefer robot-like directives.
	if strings.Contains(bodyLower, "user-agent:") ||
		strings.Contains(bodyLower, "disallow:") ||
		strings.Contains(bodyLower, "allow:") ||
		strings.Contains(bodyLower, "sitemap:") {
		return text, true
	}
	return "", false
}

func fetchOptionalSitemap(base string) (string, bool) {
	text, ctype, ok := fetchOptionalWithType(base, "/sitemap.xml")
	if !ok {
		return "", false
	}
	bodyLower := strings.ToLower(strings.TrimSpace(text))
	typeLower := strings.ToLower(ctype)

	if strings.Contains(typeLower, "text/html") ||
		strings.Contains(bodyLower, "<!doctype html") ||
		strings.Contains(bodyLower, "<html") {
		return "", false
	}
	if strings.Contains(typeLower, "xml") ||
		strings.Contains(bodyLower, "<urlset") ||
		strings.Contains(bodyLower, "<sitemapindex") {
		return text, true
	}
	return "", false
}

func fetchOptionalWithType(base, p string) (string, string, bool) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", "", false
	}
	ref, err := url.Parse(p)
	if err != nil {
		return "", "", false
	}

	u := baseURL.ResolveReference(ref).String()
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024))
	if err != nil {
		return "", "", false
	}
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "", "", false
	}
	return s, resp.Header.Get("Content-Type"), true
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}
