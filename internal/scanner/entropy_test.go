package scanner

import (
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	// Simple repeated or low variance string
	entLow := shannonEntropy("password")
	if entLow > 3.0 {
		t.Errorf("Expected low entropy for 'password', got %f", entLow)
	}

	// High variance alphanumeric string mapping to secrets
	entHigh := shannonEntropy("AIzaSyCXwabcde1234567890fghijkLMNOPQrs")
	if entHigh < 3.5 {
		t.Errorf("Expected high entropy for random string, got %f", entHigh)
	}
}

func TestTruncate(t *testing.T) {
	short := truncate("short", 10)
	if short != "short" {
		t.Errorf("Expected 'short', got %s", short)
	}

	long := truncate("this is a very long string", 10)
	if long != "this is a ..." {
		t.Errorf("Expected 'this is a ...', got %s", long)
	}
}
