package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"strings"

	"surisc/internal/scanner"
)

const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cleanArgs, informative, informativeScope, err := parseInformativeArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	flags := flag.NewFlagSet("surisc", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	targetURL := flags.String("u", "", "Target URL to scan")
	outputFormat := flags.String("o", "hud", "Output format (hud|json)")
	if err := flags.Parse(cleanArgs); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitError
	}

	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "Please provide a target URL using the -u flag.")
		return exitError
	}

	if err := scanner.ValidateTargetReachable(*targetURL); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitError
	}

	leaks, insight := scanner.RunScan(*targetURL, informative)

	if *outputFormat == "json" {
		if informative {
			b, err := json.MarshalIndent(insight, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal json: %v\n", err)
				return exitError
			}
			fmt.Println(string(b))
		} else {
			b, err := json.MarshalIndent(leaks, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal json: %v\n", err)
				return exitError
			}
			fmt.Println(string(b))
		}
	} else {
		// HUD Output
		if informative {
			fmt.Println("\n🛰️  Surisc Informative Target Analysis:")

			showAll := informativeScope == "all"
			showServerInfo := showAll || informativeScope == "webinfo"
			showRoutes := showAll || informativeScope == "routes"
			showRobots := showAll || informativeScope == "robots"
			showSitemaps := showAll || informativeScope == "sitemaps"

			if showServerInfo {
				printInfoTable([][2]string{
					{"Backend", insight.Backend},
					{"Frontend", insight.Frontend},
					{"Hosting", insight.Hosting},
					{"Server", insight.Server},
					{"Protocol", insight.Protocol},
					{"CDN/WAF", insight.CDNWAF},
					{"CMS", insight.CMS},
					{"SPA", insight.SPA},
					{"PWA", insight.PWA},
					{"CSP", insight.ContentSecurityPolicy},
					{"X-Frame-Options", insight.XFrameOptions},
					{"HSTS", insight.StrictTransportSecurity},
					{"ACAO", insight.AccessControlAllowOrigin},
					{"Cookie Security", fmt.Sprintf("%d findings", len(insight.CookieSecurity))},
					{"JWT Indicators", fmt.Sprintf("%d findings", len(insight.JWTIndicators))},
					{"API Specs", fmt.Sprintf("%d found", len(insight.APISpecs))},
					{"GraphQL Introspection", orDefault(insight.GraphQLIntrospection, "-")},
				})
			}
			if showRoutes && len(insight.Routes) > 0 {
				printListSection("Routes", insight.Routes)
			}
			if showRoutes && len(insight.ProbedRoutes) > 0 {
				printListSection("Hidden Routes / Attack Surface", insight.ProbedRoutes)
			}
			if showRoutes && len(insight.APISpecs) > 0 {
				printListSection("API Specifications", insight.APISpecs)
			}
			if showRobots && insight.RobotsTxt != "" {
				printRobotsTable(insight.RobotsTxt)
			}
			if showSitemaps && insight.SitemapXML != "" {
				printSitemapTable(insight.SitemapXML)
			}

			hasOutput := false
			if showServerInfo && (insight.Backend != "" || insight.Frontend != "" || insight.Hosting != "" || insight.Server != "" || insight.CDNWAF != "" || insight.CMS != "" || insight.Protocol != "" || insight.SPA != "" || insight.PWA != "" || insight.ContentSecurityPolicy != "" || insight.XFrameOptions != "" || insight.StrictTransportSecurity != "" || insight.AccessControlAllowOrigin != "" || len(insight.CookieSecurity) > 0 || len(insight.JWTIndicators) > 0 || len(insight.APISpecs) > 0 || insight.GraphQLIntrospection != "") {
				hasOutput = true
			}
			if showRoutes && len(insight.Routes) > 0 {
				hasOutput = true
			}
			if showRoutes && len(insight.ProbedRoutes) > 0 {
				hasOutput = true
			}
			if showRobots && insight.RobotsTxt != "" {
				hasOutput = true
			}
			if showSitemaps && insight.SitemapXML != "" {
				hasOutput = true
			}
			if showServerInfo && len(insight.CookieSecurity) > 0 {
				printListSection("Cookie Security", insight.CookieSecurity)
			}
			if showServerInfo && len(insight.JWTIndicators) > 0 {
				printListSection("JWT Indicators", insight.JWTIndicators)
			}

			if !hasOutput {
				fmt.Println("- No technology insights detected.")
			}
			fmt.Println(strings.Repeat("-", 68))
			return exitOK
		}

		fmt.Println("\n🛰️  Surisc Completed. Results:")
		fmt.Println(strings.Repeat("-", 68))
		if len(leaks) == 0 {
			fmt.Println("No leaks detected or target could not be reached.")
		}
		for _, leak := range leaks {
			fmt.Printf("[!]\t[%s]\n\t[SOURCE_URL]: %s\n\t[GRAVITY_SCORE]: %.2f\n\t[SNIPPET]: %s\n",
				leak.LeakType, leak.SourceURL, leak.GravityScore, leak.Snippet)
			fmt.Println(strings.Repeat("-", 68))
		}
	}

	return exitCodeFor(len(leaks))
}

func exitCodeFor(findings int) int {
	if findings > 0 {
		return exitFindings
	}
	return exitOK
}

func parseInformativeArgs(args []string) ([]string, bool, string, error) {
	scope := "all"
	informative := false
	clean := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-i=") {
			informative = true
			next := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(arg, "-i=")))
			switch next {
			case "", "all":
				scope = "all"
			case "robots", "routes", "sitemaps", "webinfo":
				scope = next
			default:
				return nil, false, "", fmt.Errorf("invalid -i value %q; use webinfo|robots|routes|sitemaps or leave blank", next)
			}
			continue
		}
		if arg != "-i" {
			clean = append(clean, arg)
			continue
		}

		informative = true
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			next := strings.ToLower(strings.TrimSpace(args[i+1]))
			switch next {
			case "", "all":
				scope = "all"
			case "robots", "routes", "sitemaps", "webinfo":
				scope = next
			default:
				return nil, false, "", fmt.Errorf("invalid -i value %q; use webinfo|robots|routes|sitemaps or leave blank", next)
			}
			i++
		}
	}

	return clean, informative, scope, nil
}

func printInfoTable(rows [][2]string) {
	w := terminalWidth()
	if w < 60 {
		// Fallback to simple list for very narrow terminals
		for _, row := range rows {
			val := row[1]
			if val == "" {
				val = "-"
			}
			fmt.Printf("  %s: %s\n", row[0], val)
		}
		return
	}
	// 68-char table fits comfortably even in narrower terminals
	fmt.Println(strings.Repeat("-", 68))
	fmt.Printf("  %-16s  %-45s\n", "Field", "Value")
	fmt.Printf("  %s  %s\n", strings.Repeat("-", 16), strings.Repeat("-", 45))
	for _, row := range rows {
		val := row[1]
		if val == "" {
			val = "-"
		}
		fmt.Printf("  %-16s  %-45s\n", row[0], truncateLine(val, 45))
	}
	fmt.Println(strings.Repeat("-", 68))
}

func terminalWidth() int {
	// Default to a safe 68-char width; no platform-specific ioctl calls.
	return 68
}

func printListSection(title string, items []string) {
	fmt.Printf("\n[%s]\n", title)
	fmt.Println(strings.Repeat("-", 68))
	for _, item := range items {
		fmt.Printf("- %s\n", item)
	}
}

func printTwoColumnTable(title, colA, colB string, rows [][2]string) {
	fmt.Printf("\n[%s]\n", title)
	fmt.Println(strings.Repeat("-", 68))
	fmt.Printf("  %-16s  %-45s\n", colA, colB)
	fmt.Printf("  %s  %s\n", strings.Repeat("-", 16), strings.Repeat("-", 45))
	for _, row := range rows {
		fmt.Printf("  %-16s  %-45s\n", truncateLine(row[0], 16), truncateLine(row[1], 45))
	}
}

func printRobotsTable(content string) {
	lines := strings.Split(content, "\n")
	rows := make([][2]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			rows = append(rows, [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
		} else {
			rows = append(rows, [2]string{line, ""})
		}
	}
	if len(rows) == 0 {
		rows = append(rows, [2]string{"-", "No robots directives found"})
	}
	printTwoColumnTable("robots.txt", "Directive", "Value", rows)
}

func printSitemapTable(content string) {
	rows := make([][2]string, 0, 16)
	decoder := xml.NewDecoder(strings.NewReader(content))
	index := 1
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok || strings.ToLower(start.Name.Local) != "loc" {
			continue
		}
		var loc string
		if err := decoder.DecodeElement(&loc, &start); err == nil {
			loc = strings.TrimSpace(loc)
			if loc != "" {
				rows = append(rows, [2]string{fmt.Sprintf("%d", index), loc})
				index++
			}
		}
	}
	if len(rows) == 0 {
		rows = append(rows, [2]string{"-", "No <loc> entries parsed"})
	}
	printTwoColumnTable("sitemap.xml", "#", "Location", rows)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncateLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
