package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"surisc/internal/scanner"
)

func main() {
	targetURL := flag.String("u", "", "Target URL to scan")
	outputFormat := flag.String("o", "hud", "Output format (hud|json)")
	informative := flag.Bool("i", false, "Enable informative technology stack detection")
	flag.Parse()

	if *targetURL == "" {
		log.Fatal("Please provide a target URL using the -u flag.")
	}

	leaks, insight := scanner.RunScan(*targetURL, *informative)

	if *outputFormat == "json" {
		if *informative {
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
		if *informative {
			fmt.Println("\n🛰️  Surisc Informative Target Analysis:")
			fmt.Println(strings.Repeat("-", 80))
			if insight.Backend != "" { fmt.Printf("- Backend: %s\n", insight.Backend) }
			if insight.Frontend != "" { fmt.Printf("- Frontend: %s\n", insight.Frontend) }
			if insight.Server != "" { fmt.Printf("- Server: %s\n", insight.Server) }
			if insight.Protocol != "" { fmt.Printf("- Protocol: %s\n", insight.Protocol) }
			if insight.CDNWAF != "" { fmt.Printf("- CDN/WAF: %s\n", insight.CDNWAF) }
			if insight.CMS != "" { fmt.Printf("- CMS: %s\n", insight.CMS) }
			if insight.Backend == "" && insight.Frontend == "" && insight.Server == "" && insight.CDNWAF == "" && insight.CMS == "" && insight.Protocol == "" {
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
