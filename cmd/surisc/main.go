package main

import (
	"encoding/xml"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"surisc/internal/scanner"
)

func main() {
	cleanArgs, informative, informativeScope, err := parseInformativeArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	targetURL := flag.String("u", "", "Target URL to scan")
	outputFormat := flag.String("o", "hud", "Output format (hud|json)")
	flag.CommandLine.Parse(cleanArgs)

	if *targetURL == "" {
		log.Fatal("Please provide a target URL using the -u flag.")
	}

	leaks, insight := scanner.RunScan(*targetURL, informative)

	if *outputFormat == "json" {
		if informative {
			b, err := json.MarshalIndent(insight, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal json: %v", err)
			}
			fmt.Println(string(b))
		} else {
			b, err := json.MarshalIndent(leaks, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal json: %v", err)
			}
			fmt.Println(string(b))
		}
	} else {
		// HUD Output
		if informative {
			fmt.Println("\n🛰️  Surisc Informative Target Analysis:")

			showAll := informativeScope == "all"
			showServerInfo := showAll || informativeScope == "serverinfo"
			showRoutes := showAll || informativeScope == "routes"
			showRobots := showAll || informativeScope == "robots"
			showSitemaps := showAll || informativeScope == "sitemaps"

			if showServerInfo {
				printInfoTable([][2]string{
					{"Backend", insight.Backend},
					{"Frontend", insight.Frontend},
					{"Server", insight.Server},
					{"Protocol", insight.Protocol},
					{"CDN/WAF", insight.CDNWAF},
					{"CMS", insight.CMS},
					{"SPA", insight.SPA},
					{"CSP", insight.ContentSecurityPolicy},
					{"X-Frame-Options", insight.XFrameOptions},
					{"HSTS", insight.StrictTransportSecurity},
					{"ACAO", insight.AccessControlAllowOrigin},
				})
			}
			if showRoutes && len(insight.Routes) > 0 {
				printListSection("Routes", insight.Routes)
			}
			if showRobots && insight.RobotsTxt != "" {
				printRobotsTable(insight.RobotsTxt)
			}
			if showSitemaps && insight.SitemapXML != "" {
				printSitemapTable(insight.SitemapXML)
			}

			hasOutput := false
			if showServerInfo && (insight.Backend != "" || insight.Frontend != "" || insight.Server != "" || insight.CDNWAF != "" || insight.CMS != "" || insight.Protocol != "" || insight.SPA != "" || insight.ContentSecurityPolicy != "" || insight.XFrameOptions != "" || insight.StrictTransportSecurity != "" || insight.AccessControlAllowOrigin != "") {
				hasOutput = true
			}
			if showRoutes && len(insight.Routes) > 0 {
				hasOutput = true
			}
			if showRobots && insight.RobotsTxt != "" {
				hasOutput = true
			}
			if showSitemaps && insight.SitemapXML != "" {
				hasOutput = true
			}

			if !hasOutput {
				fmt.Println("- No technology insights detected.")
			}
			fmt.Println(strings.Repeat("-", 80))
			return
		}

		fmt.Println("\n🛰️  Surisc Completed. Results:")
		fmt.Println(strings.Repeat("-", 80))
		if len(leaks) == 0 {
			fmt.Println("No leaks detected or target could not be reached.")
		}
		for _, leak := range leaks {
			fmt.Printf("[!]\t[%s]\n\t[SOURCE_URL]: %s\n\t[GRAVITY_SCORE]: %.2f\n\t[SNIPPET]: %s\n",
				leak.LeakType, leak.SourceURL, leak.GravityScore, leak.Snippet)
			fmt.Println(strings.Repeat("-", 80))
		}
	}
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
			case "robots", "routes", "sitemaps", "serverinfo":
				scope = next
			default:
				return nil, false, "", fmt.Errorf("invalid -i value %q; use serverinfo|robots|routes|sitemaps or leave blank", next)
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
			case "robots", "routes", "sitemaps", "serverinfo":
				scope = next
			default:
				return nil, false, "", fmt.Errorf("invalid -i value %q; use serverinfo|robots|routes|sitemaps or leave blank", next)
			}
			i++
		}
	}

	return clean, informative, scope, nil
}

func printInfoTable(rows [][2]string) {
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("| %-16s | %-57s |\n", "Field", "Value")
	fmt.Printf("|%s|%s|\n", strings.Repeat("-", 18), strings.Repeat("-", 59))
	for _, row := range rows {
		val := row[1]
		if val == "" {
			val = "-"
		}
		fmt.Printf("| %-16s | %-57s |\n", row[0], truncateLine(val, 57))
	}
	fmt.Println(strings.Repeat("-", 80))
}

func printListSection(title string, items []string) {
	fmt.Printf("\n[%s]\n", title)
	fmt.Println(strings.Repeat("-", 80))
	for _, item := range items {
		fmt.Printf("- %s\n", item)
	}
}

func printTwoColumnTable(title, colA, colB string, rows [][2]string) {
	fmt.Printf("\n[%s]\n", title)
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("| %-20s | %-54s |\n", colA, colB)
	fmt.Printf("|%s|%s|\n", strings.Repeat("-", 22), strings.Repeat("-", 56))
	for _, row := range rows {
		fmt.Printf("| %-20s | %-54s |\n", truncateLine(row[0], 20), truncateLine(row[1], 54))
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

func truncateLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
