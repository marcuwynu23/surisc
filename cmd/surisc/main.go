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
	flag.Parse()

	if *targetURL == "" {
		log.Fatal("Please provide a target URL using the -u flag.")
	}

	leaks := scanner.RunScan(*targetURL)

	if *outputFormat == "json" {
		b, err := json.MarshalIndent(leaks, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal json: %v", err)
		}
		fmt.Println(string(b))
	} else {
		// HUD Output
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
