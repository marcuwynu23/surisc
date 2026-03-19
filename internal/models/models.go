package models

// LeakType represents the category of the find
type LeakType string

const (
	LeakTypeHighEntropy LeakType = "HIGH_ENTROPY_SECRET"
	LeakTypeFirebaseKey LeakType = "FIREBASE_API_KEY"
	LeakTypeMapFile     LeakType = "MAP_FILE_REFERENCE"
	LeakTypeBearerToken LeakType = "BEARER_TOKEN"
	LeakTypeInternalIP  LeakType = "INTERNAL_IP_ADDRESS"
	LeakTypeImportMeta  LeakType = "IMPORT_META_LEAK"
	LeakTypeGenericSec  LeakType = "GENERIC_SECRET_KEY"
)

type Leak struct {
	LeakType     LeakType `json:"leak_type"`
	SourceURL    string   `json:"source_url"`
	GravityScore float64  `json:"gravity_score"`
	Snippet      string   `json:"snippet,omitempty"`
}
