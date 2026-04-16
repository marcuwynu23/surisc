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
		r.Headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		r.Headers.Set("Accept-Language", "en-US,en;q=0.9")
		r.Headers.Set("Cache-Control", "max-age=0")
		r.Headers.Set("Connection", "keep-alive")
		r.Headers.Set("DNT", "1")
		r.Headers.Set("Pragma", "no-cache")
		r.Headers.Set("Sec-Fetch-Dest", "document")
		r.Headers.Set("Sec-Fetch-Mode", "navigate")
		r.Headers.Set("Sec-Fetch-Site", "none")
		r.Headers.Set("Sec-Fetch-User", "?1")
		r.Headers.Set("Sec-CH-UA", `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="99"`)
		r.Headers.Set("Sec-CH-UA-Mobile", "?0")
		r.Headers.Set("Sec-CH-UA-Platform", `"Windows"`)
		r.Headers.Set("Upgrade-Insecure-Requests", "1")
	})

	var leaks []models.Leak
	var insight models.TechInsight
	var leaksMutex sync.Mutex
	var insightMutex sync.Mutex
	var routesMutex sync.Mutex
	var contentRoutesMutex sync.Mutex
	var techMutex sync.Mutex
	routeSet := make(map[string]struct{})
	contentRouteSet := make(map[string]struct{})
	techSet := make(map[string]struct{})
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
			applyBrowserHeaders(req)
			client := &http.Client{Timeout: 5 * time.Second}
			if resp, err := client.Do(req); err == nil {
				insightMutex.Lock()
				insight.Protocol = resp.Proto
				if insight.Hosting == "" {
					insight.Hosting = detectHostingProvider(baseTarget, resp.Request.URL, resp.Header, nil)
				}
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
		insight.SPA = "Yes"
		addTech("Next.js", techSet, &techMutex)
		addTech("React", techSet, &techMutex)
	})

	c.OnHTML("div[id=root], div[id=app], script[type=module]", func(e *colly.HTMLElement) {
		insightMutex.Lock()
		defer insightMutex.Unlock()
		if insight.SPA == "" {
			insight.SPA = "Yes"
		}
	})

	// Alpine.js frequently uses x-* attributes directly in HTML templates.
	c.OnHTML("[x-data], [x-init], [x-show], [x-model], [x-bind], [x-cloak], [x-transition], [x-ref], [x-text], [x-html]", func(e *colly.HTMLElement) {
		addTech("Alpine.js", techSet, &techMutex)
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
		if !isCrawlableResourceRef(src) {
			src = ""
		}

		// Tech Insights from script paths
		if src != "" {
			addTechFromURL(src, techSet, &techMutex)
			insightMutex.Lock()
			if strings.Contains(src, "/_next/") {
				insight.SPA = "Yes"
				addTech("Next.js", techSet, &techMutex)
				addTech("React", techSet, &techMutex)
			} else if strings.Contains(src, "/_nuxt/") {
				insight.SPA = "Yes"
				addTech("Nuxt.js", techSet, &techMutex)
				addTech("Vue.js", techSet, &techMutex)
			} else if strings.Contains(src, "wp-includes") || strings.Contains(src, "wp-content") {
				insight.CMS = "WordPress"
				insight.Backend = "PHP (WordPress)"
				addTech("WordPress", techSet, &techMutex)
			}
			insightMutex.Unlock()
		}

		if src == "" && !informativeOnly {
			// Inline script (secret scan mode only)
			content := e.Text
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzeContent(e.Request.URL.String(), []byte(content), &leaks, &leaksMutex)
			}()
			return
		}

		// External script: always fetch so informative mode can fingerprint tech.
		if src != "" {
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
		if detected := detectHostingProvider(baseTarget, r.Request.URL, *r.Headers, r.Body); shouldUpgradeHosting(insight.Hosting, detected) {
			insight.Hosting = detected
		}
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
		// Fingerprint frontend technologies from URL + content.
		if r.Request != nil && r.Request.URL != nil {
			addTechFromURL(r.Request.URL.Path, techSet, &techMutex)
		}
		addTechFromBody(ctype, r.Body, techSet, &techMutex)

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
			extractRoutesFromContent(r.Body, r.Request.URL, contentRouteSet, &contentRoutesMutex)
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
	if informativeOnly {
		mergeValidatedContentRoutes(targetURL, routeSet, contentRouteSet, &routesMutex)
	}
	insight.Routes = sortedRoutes(routeSet)
	insight.PWA = classifyPWA(insight.Routes)
	front := sortedTech(techSet)
	front = ensureVanillaFrontend(front)
	if len(front) > 0 {
		insight.Frontend = strings.Join(front, ", ")
	}
	if insight.Frontend == "" && strings.EqualFold(insight.CMS, "WordPress") {
		insight.Frontend = "WordPress"
	}

	return leaks, insight
}

func addTech(name string, techSet map[string]struct{}, mu *sync.Mutex) {
	if name == "" {
		return
	}
	mu.Lock()
	techSet[name] = struct{}{}
	mu.Unlock()
}

func sortedTech(techSet map[string]struct{}) []string {
	if len(techSet) == 0 {
		return nil
	}
	out := make([]string, 0, len(techSet))
	for k := range techSet {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ensureVanillaFrontend(front []string) []string {
	if len(front) == 0 {
		return []string{"Vanilla JS"}
	}
	frameworks := map[string]struct{}{
		"React":       {},
		"Vue.js":      {},
		"Angular":     {},
		"Svelte":      {},
		"SolidJS":     {},
		"Alpine.js":   {},
		"Next.js":     {},
		"Nuxt.js":     {},
		"Remix":       {},
		"Astro":       {},
		"Ember.js":    {},
		"Backbone.js": {},
	}
	hasFramework := false
	hasVanilla := false
	for _, t := range front {
		if t == "Vanilla JS" {
			hasVanilla = true
		}
		if _, ok := frameworks[t]; ok {
			hasFramework = true
		}
	}
	if hasFramework || hasVanilla {
		return front
	}
	out := append([]string{}, front...)
	out = append(out, "Vanilla JS")
	sort.Strings(out)
	return out
}

func detectHostingProvider(baseTarget, requestURL *url.URL, headers http.Header, body []byte) string {
	getHeaderLower := func(name string) string {
		return strings.ToLower(strings.TrimSpace(headers.Get(name)))
	}
	server := getHeaderLower("Server")
	via := getHeaderLower("Via")

	host := ""
	if requestURL != nil && requestURL.Hostname() != "" {
		host = strings.ToLower(requestURL.Hostname())
	} else if baseTarget != nil {
		host = strings.ToLower(baseTarget.Hostname())
	}

	type candidate struct {
		name  string
		score int
	}
	best := candidate{}
	add := func(name string, score int) {
		if score > best.score {
			best = candidate{name: name, score: score}
		}
	}
	headerExists := func(name string) bool {
		return strings.TrimSpace(headers.Get(name)) != ""
	}
	hostHas := func(suffix string) bool {
		return host != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
	}

	// Vercel
	if headerExists("X-Vercel-Id") || headerExists("X-Vercel-Cache") || strings.Contains(server, "vercel") || hostHas("vercel.app") {
		score := 80
		if headerExists("X-Vercel-Id") {
			score = 100
		}
		add("Vercel", score)
	}
	// Netlify
	if headerExists("X-Nf-Request-Id") || strings.Contains(server, "netlify") || hostHas("netlify.app") {
		score := 80
		if headerExists("X-Nf-Request-Id") {
			score = 100
		}
		add("Netlify", score)
	}
	// Heroku
	if strings.Contains(via, "vegur") || strings.Contains(server, "heroku") || hostHas("herokuapp.com") {
		score := 85
		if strings.Contains(via, "vegur") {
			score = 100
		}
		add("Heroku", score)
	}
	// Railway
	if headerExists("X-Railway-Request-Id") || strings.Contains(server, "railway") || hostHas("railway.app") || hostHas("up.railway.app") {
		score := 85
		if headerExists("X-Railway-Request-Id") {
			score = 100
		}
		add("Railway", score)
	}
	isCloudflareEdge := headerExists("CF-Ray") || strings.Contains(server, "cloudflare")
	// Cloudflare Workers
	if hostHas("workers.dev") || headerExists("CF-Worker") {
		add("Cloudflare Workers", 100)
	}
	// Cloudflare Pages (host + code/header signatures)
	if hostHas("pages.dev") || hasCloudflarePagesHeaderSignal(headers) || hasCloudflarePagesCodeSignal(body) {
		add("Cloudflare Pages", 100)
	} else if isCloudflareEdge {
		// Cloudflare edge detected, but origin platform may still be external (e.g. VPS/origin app).
		add("Cloudflare Proxied", 88)
	}
	// GitHub Pages
	if strings.Contains(server, "github.com") || headerExists("X-GitHub-Request-Id") || hostHas("github.io") {
		add("GitHub Pages", 95)
	}
	// GitLab Pages
	if strings.Contains(server, "gitlab") || hostHas("gitlab.io") {
		add("GitLab Pages", 90)
	}
	// Render
	if strings.Contains(server, "render") || hostHas("onrender.com") {
		add("Render", 90)
	}
	// Fly.io
	if strings.Contains(server, "fly.io") || headerExists("Fly-Request-Id") || hostHas("fly.dev") {
		add("Fly.io", 90)
	}
	// Firebase Hosting
	if headerExists("X-Firebase-Request-Id") || hostHas("web.app") || hostHas("firebaseapp.com") {
		add("Firebase Hosting", 95)
	}
	// AWS Amplify
	if hostHas("amplifyapp.com") {
		add("AWS Amplify", 95)
	}
	// Azure Static Web Apps
	if hostHas("azurestaticapps.net") || headerExists("X-Azure-Ref") {
		add("Azure Static Web Apps", 90)
	}
	// Surge
	if strings.Contains(server, "surge") || hostHas("surge.sh") {
		add("Surge", 90)
	}
	// Glitch
	if hostHas("glitch.me") {
		add("Glitch", 90)
	}

	if best.score >= 80 {
		return best.name
	}
	return ""
}

func hasCloudflarePagesCodeSignal(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	s := strings.ToLower(string(body))
	signals := []string{
		"cloudflare pages",
		"pages.dev",
		"deployed on cloudflare pages",
		"<!-- cloudflare pages -->",
		`meta name="generator" content="cloudflare pages"`,
		`meta name='generator' content='cloudflare pages'`,
	}
	for _, sig := range signals {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

func hasCloudflarePagesHeaderSignal(headers http.Header) bool {
	getLower := func(name string) string {
		return strings.ToLower(strings.TrimSpace(headers.Get(name)))
	}
	isCloudflareEdge := getLower("cf-ray") != "" || strings.Contains(getLower("server"), "cloudflare")
	if !isCloudflareEdge {
		return false
	}

	// Strong signal for deployed static apps on Cloudflare edge.
	if strings.Contains(getLower("x-powered-by"), "cloudflare pages") {
		return true
	}

	// If origin fingerprints are present, prefer "Cloudflare Proxied".
	if hasOriginServerFingerprint(headers) {
		return false
	}

	score := 0
	if strings.Contains(getLower("cache-control"), "must-revalidate") && strings.Contains(getLower("cache-control"), "max-age=0") {
		score++
	}
	if strings.Contains(getLower("speculation-rules"), "/cdn-cgi/speculation") {
		score++
	}
	if getLower("cf-cache-status") != "" {
		score++
	}
	if strings.Contains(getLower("strict-transport-security"), "preload") {
		score++
	}

	return score >= 3
}

func hasOriginServerFingerprint(headers http.Header) bool {
	xPoweredBy := strings.ToLower(strings.TrimSpace(headers.Get("X-Powered-By")))
	if xPoweredBy != "" && !strings.Contains(xPoweredBy, "cloudflare pages") {
		return true
	}
	originHeaders := []string{
		"X-Generator",
		"X-Drupal-Cache",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Pingback",
	}
	for _, h := range originHeaders {
		if strings.TrimSpace(headers.Get(h)) != "" {
			return true
		}
	}
	return false
}

func shouldUpgradeHosting(current, next string) bool {
	if next == "" {
		return false
	}
	if current == "" {
		return true
	}
	return hostingRank(next) > hostingRank(current)
}

func hostingRank(hosting string) int {
	switch hosting {
	case "Cloudflare Workers", "Cloudflare Pages":
		return 100
	case "Cloudflare Proxied":
		return 70
	default:
		return 90
	}
}

func addTechFromURL(path string, techSet map[string]struct{}, mu *sync.Mutex) {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/_next/"):
		addTech("Next.js", techSet, mu)
		addTech("React", techSet, mu)
	case strings.Contains(p, "/_nuxt/"):
		addTech("Nuxt.js", techSet, mu)
		addTech("Vue.js", techSet, mu)
	case strings.Contains(p, "/@vite/") || strings.Contains(p, "vite") || strings.Contains(p, "registersw.js"):
		addTech("Vite", techSet, mu)
	case strings.Contains(p, "/astro") || strings.Contains(p, "astro"):
		addTech("Astro", techSet, mu)
	case strings.Contains(p, "remix"):
		addTech("Remix", techSet, mu)
	case strings.Contains(p, "alpine"):
		addTech("Alpine.js", techSet, mu)
	case strings.Contains(p, "svelte"):
		addTech("Svelte", techSet, mu)
	case strings.Contains(p, "solid"):
		addTech("SolidJS", techSet, mu)
	case strings.Contains(p, "angular"):
		addTech("Angular", techSet, mu)
	case strings.Contains(p, "ember"):
		addTech("Ember.js", techSet, mu)
	case strings.Contains(p, "backbone"):
		addTech("Backbone.js", techSet, mu)
	case strings.Contains(p, "wp-content") || strings.Contains(p, "wp-includes"):
		addTech("WordPress", techSet, mu)
	case strings.Contains(p, "cdn.shopify.com") || strings.Contains(p, "/shopify") || strings.Contains(p, "shopify"):
		addTech("Shopify", techSet, mu)
	}
}

func addTechFromBody(contentType string, body []byte, techSet map[string]struct{}, mu *sync.Mutex) {
	ct := strings.ToLower(contentType)
	// Only scan likely text-like bodies.
	if !(strings.Contains(ct, "html") || strings.Contains(ct, "javascript") || strings.Contains(ct, "json") || strings.Contains(ct, "text/")) {
		return
	}
	s := strings.ToLower(string(body))

	// Framework-specific signatures (best-effort heuristics).
	if strings.Contains(s, "/@vite/client") || strings.Contains(s, "vite") && strings.Contains(s, "import.meta") {
		addTech("Vite", techSet, mu)
	}
	if strings.Contains(s, "data-astro-cid") || strings.Contains(s, "astro-island") || strings.Contains(s, "astro:page-load") {
		addTech("Astro", techSet, mu)
	}
	if strings.Contains(s, "__nuxt__") || strings.Contains(s, "nuxt") && strings.Contains(s, "/_nuxt/") {
		addTech("Nuxt.js", techSet, mu)
		addTech("Vue.js", techSet, mu)
	}
	if strings.Contains(s, "/_next/") || strings.Contains(s, "__next_data__") {
		addTech("Next.js", techSet, mu)
		addTech("React", techSet, mu)
	}
	if strings.Contains(s, `from "react"`) || strings.Contains(s, `from 'react'`) || strings.Contains(s, `require("react")`) || strings.Contains(s, `require('react')`) ||
		strings.Contains(s, "react-dom") || strings.Contains(s, "react.createelement") || strings.Contains(s, "jsxruntime") {
		addTech("React", techSet, mu)
	}
	if strings.Contains(s, "__vue__") || strings.Contains(s, "createapp(") && strings.Contains(s, "vue") {
		addTech("Vue.js", techSet, mu)
	}
	if strings.Contains(s, "ng-version") || strings.Contains(s, "angular") && strings.Contains(s, "zone.js") {
		addTech("Angular", techSet, mu)
	}
	if strings.Contains(s, "svelte/internal") || strings.Contains(s, "svelte") && strings.Contains(s, "hydration") {
		addTech("Svelte", techSet, mu)
	}
	if strings.Contains(s, "solid-js") || strings.Contains(s, "createsignal") {
		addTech("SolidJS", techSet, mu)
	}
	if strings.Contains(s, "alpinejs") ||
		strings.Contains(s, "x-data") ||
		strings.Contains(s, "x-init") ||
		strings.Contains(s, "x-show") ||
		strings.Contains(s, "x-model") ||
		strings.Contains(s, "x-bind:") ||
		strings.Contains(s, "x-on:") ||
		strings.Contains(s, "@click") {
		addTech("Alpine.js", techSet, mu)
	}
	if strings.Contains(s, "__remixcontext") || strings.Contains(s, "data-remix") {
		addTech("Remix", techSet, mu)
	}
	if strings.Contains(s, "ember") && (strings.Contains(s, "emberenv") || strings.Contains(s, "ember-view")) {
		addTech("Ember.js", techSet, mu)
	}
	if strings.Contains(s, "backbone.model") || strings.Contains(s, "backbone.view") {
		addTech("Backbone.js", techSet, mu)
	}
	if isLikelyWordPressBody(s) {
		addTech("WordPress", techSet, mu)
	}
	if strings.Contains(s, "cdn.shopify.com") || strings.Contains(s, "shopify.theme") || strings.Contains(s, "shopify.shop") || strings.Contains(s, "window.shopify") || strings.Contains(s, "myshopify.com") || strings.Contains(s, "shopify-checkout-api-token") || strings.Contains(s, "x-shopify-stage") {
		addTech("Shopify", techSet, mu)
	}
}

func classifyPWA(routes []string) string {
	hasManifest := false
	hasSW := false
	for _, r := range routes {
		rl := strings.ToLower(r)
		if strings.HasSuffix(rl, "manifest.webmanifest") || strings.HasSuffix(rl, "manifest.json") {
			hasManifest = true
		}
		if strings.Contains(rl, "registersw.js") || strings.Contains(rl, "service-worker") || strings.Contains(rl, "sw.js") {
			hasSW = true
		}
	}
	if hasManifest && hasSW {
		return "Yes"
	}
	if hasManifest || hasSW {
		return "Likely"
	}
	return "No"
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
	applyBrowserHeaders(req)
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
			return "Yes"
		}
	}
	return "No"
}

func isCrawlableResourceRef(raw string) bool {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return false
	}
	refURL, err := url.Parse(clean)
	if err != nil {
		return false
	}
	// Relative URLs and protocol-relative URLs are crawlable.
	if refURL.Scheme == "" {
		return true
	}
	switch strings.ToLower(refURL.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
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
	withoutFencedCode := stripMarkdownFencedCodeBlocks(content)
	matches := rxRouteLiteral.FindAllSubmatch(withoutFencedCode, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		addRoute(string(m[1]), baseURL, routeSet, mu)
	}

	absMatches := rxAbsoluteURL.FindAll(withoutFencedCode, -1)
	for _, m := range absMatches {
		addRoute(string(m), baseURL, routeSet, mu)
	}
}

func stripMarkdownFencedCodeBlocks(content []byte) []byte {
	s := string(content)
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	inFence := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

func mergeValidatedContentRoutes(base string, routeSet map[string]struct{}, candidates map[string]struct{}, mu *sync.Mutex) {
	if len(candidates) == 0 {
		return
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	paths := make([]string, 0, len(candidates))
	for p := range candidates {
		if _, ok := routeSet[p]; ok {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return
	}
	sort.Strings(paths)

	homeCT, homeBody, _, _ := fetchRouteResponse(client, baseURL, "/")
	homeSig := normalizedResponseSignature(homeCT, homeBody, paths)
	missingCT, missingBody, _, _ := fetchRouteResponse(client, baseURL, "/__surisc_nonexistent_route_probe__")
	missingSig := normalizedResponseSignature(missingCT, missingBody, paths)

	for _, p := range paths {
		ctype, body, statusCode, _ := fetchRouteResponse(client, baseURL, p)
		if statusCode == 0 || statusCode >= 400 {
			continue
		}
		normSig := normalizedResponseSignature(ctype, body, paths)
		if isLikelyFallbackResponse(ctype, normSig, homeSig, missingSig) {
			continue
		}
		// If HTML looks like generic SPA shell/fallback, keep it out of routes list.
		if statusCode == 200 && strings.Contains(strings.ToLower(ctype), "html") {
			continue
		}
		mu.Lock()
		routeSet[p] = struct{}{}
		mu.Unlock()
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
	if !isLikelyRealRoute(normalized) {
		return
	}

	mu.Lock()
	routeSet[normalized] = struct{}{}
	mu.Unlock()
}

func isLikelyWordPressBody(s string) bool {
	// Require WordPress-specific runtime/resource signals to avoid article text false positives.
	if strings.Contains(s, "wp-content/") || strings.Contains(s, "wp-includes/") {
		return true
	}
	if strings.Contains(s, "wp-json") || strings.Contains(s, "xmlrpc.php") || strings.Contains(s, "wp-admin") {
		return true
	}
	if strings.Contains(s, `name="generator"`) && strings.Contains(s, "wordpress") {
		return true
	}
	return false
}

func isLikelyRealRoute(route string) bool {
	r := strings.TrimSpace(route)
	if r == "" {
		return false
	}
	rl := strings.ToLower(r)

	// Ignore obvious placeholders/template routes and non-web path snippets.
	badFragments := []string{
		":id",
		"{id}",
		"<id>",
		"comment:/",
		"/etc/",
		"/var/",
		"/opt/",
		"/mnt/",
		"/tmp/",
		"/root/",
		"/home/",
		"/src/content/",
		".md",
		".mdx",
		".pem",
		".crt",
		".key",
		"id_rsa",
		"$path",
		"$path:",
	}
	for _, frag := range badFragments {
		if strings.Contains(rl, frag) {
			return false
		}
	}

	// Filter unusual route tokens not typical for URL paths.
	if strings.ContainsAny(r, ",\\") {
		return false
	}
	// Certificate subjects and regex-like snippets are not routable paths.
	if strings.Contains(r, "C=") && strings.Contains(r, "/ST=") {
		return false
	}
	if strings.Contains(r, "=.+") || strings.Contains(r, "/i") {
		return false
	}
	return true
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
	applyBrowserHeaders(req)

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

func applyBrowserHeaders(req *http.Request) {
	// A conservative Chrome-like header set (no cookies by default).
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("DNT", "1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="99"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
}
