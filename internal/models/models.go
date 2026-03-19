package models

// LeakType represents the category of the find
type LeakType string

const (
	LeakTypeHighEntropy LeakType = "HIGH_ENTROPY_SECRET"
	LeakTypeGoogleKey   LeakType = "GOOGLE_API_KEY"
	LeakTypeMapFile     LeakType = "MAP_FILE_REFERENCE"
	LeakTypeBearerToken LeakType = "BEARER_TOKEN"
	LeakTypeInternalIP  LeakType = "INTERNAL_IP_ADDRESS"
	LeakTypeImportMeta  LeakType = "IMPORT_META_LEAK"
	LeakTypeGenericSec  LeakType = "GENERIC_SECRET_KEY"
	LeakTypeAWSKey      LeakType = "AWS_ACCESS_KEY"
	LeakTypeStripeKey   LeakType = "STRIPE_SECRET_KEY"
	LeakTypeGitHubToken LeakType = "GITHUB_PAT"
	LeakTypeSlackToken  LeakType = "SLACK_TOKEN"
	LeakTypeGitLabToken LeakType = "GITLAB_PAT"
	LeakTypeSendGridKey LeakType = "SENDGRID_API_KEY"
	LeakTypeMailgunKey  LeakType = "MAILGUN_API_KEY"
	LeakTypeResendKey   LeakType = "RESEND_API_KEY"
	LeakTypeTwilioKey   LeakType = "TWILIO_API_KEY"
	LeakTypeSquareToken LeakType = "SQUARE_ACCESS_TOKEN"
	LeakTypeRSAPrivate  LeakType = "RSA_PRIVATE_KEY"
)

type Leak struct {
	LeakType     LeakType `json:"leak_type"`
	SourceURL    string   `json:"source_url"`
	GravityScore float64  `json:"gravity_score"`
	Snippet      string   `json:"snippet,omitempty"`
}

type TechInsight struct {
	Backend  string `json:"backend,omitempty"`
	Frontend string `json:"frontend,omitempty"`
	Server   string `json:"server,omitempty"`
	CDNWAF   string `json:"cdn_waf,omitempty"`
	CMS      string `json:"cms,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}
