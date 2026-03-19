package scanner

import (
	"log"
	"math"
	"regexp"
	"strings"
	"sync"

	"surisc/internal/models"
	colly "github.com/gocolly/colly/v2"
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
	rxTwilioKey        = regexp.MustCompile(`(?:SK|AC)[a-z0-9]{32}`)
	rxSquareToken      = regexp.MustCompile(`sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`)
	rxRSAPrivate       = regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`)
	rxMapFile          = regexp.MustCompile(`sourceMappingURL=.*\.map`)
	rxBearerToken      = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`)
	rxInternalIP       = regexp.MustCompile(`(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`)
	rxImportMeta       = regexp.MustCompile(`import\.meta\.[A-Za-z0-9_\.]+`)
	rxSecretAssignment = regexp.MustCompile(`(?i)(?:api_?key|apikey|secret|token|password)[a-z0-9_]*["']?\s*[:=]\s*["']([A-Za-z0-9\-_=+\/]{12,})["']`)
	rxSecretString     = regexp.MustCompile(`(?i)["'][a-z0-9_]*(?:api_?key|apikey|secret|token|password)[a-z0-9_]*["']`)
	rxPotentialSecret  = regexp.MustCompile(`["'][A-Za-z0-9/+=]{20,}["']`)
)

func RunScan(targetURL string) []models.Leak {
	c := colly.NewCollector(
		colly.Async(true),
	)

	var leaks []models.Leak
	var leaksMutex sync.Mutex
	var wg sync.WaitGroup

	err := c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 10,
	})
	if err != nil {
		log.Fatalf("Failed to set limit rule: %v", err)
	}

	// Intercept inline scripts and <script src="...">
	c.OnHTML("script", func(e *colly.HTMLElement) {
		src := e.Attr("src")
		if src == "" {
			// Inline script
			content := e.Text
			wg.Add(1)
			go func() {
				defer wg.Done()
				analyzeContent(e.Request.URL.String(), []byte(content), &leaks, &leaksMutex)
			}()
		} else {
			// External script
			absURL := e.Request.AbsoluteURL(src)
			if absURL != "" {
				e.Request.Visit(absURL)
			}
		}
	})

	// Process JS responses
	c.OnResponse(func(r *colly.Response) {
		ctype := r.Headers.Get("Content-Type")
		if strings.Contains(ctype, "javascript") || strings.Contains(ctype, "json") || strings.HasSuffix(r.Request.URL.Path, ".js") {
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

	return leaks
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

	// 1.6 SendGrid, Mailgun, Twilio, Square
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

	// 1.7 RSA Private Keys
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

			if len(secret) > 20 && !strings.HasPrefix(secret, "AGFzbQE") && !strings.HasPrefix(secret, "AIza") && !strings.Contains(secret, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") {
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
				if shannonEntropy(val) > 3.0 && !strings.Contains(valLower, "your_") && !strings.Contains(valLower, "example") {
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
