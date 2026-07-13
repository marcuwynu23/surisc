package models

// LeakType represents the category of the find
type LeakType string

const (
	LeakTypeHighEntropy  LeakType = "HIGH_ENTROPY_SECRET"
	LeakTypeGoogleKey    LeakType = "GOOGLE_API_KEY"
	LeakTypeMapFile      LeakType = "MAP_FILE_REFERENCE"
	LeakTypeBearerToken  LeakType = "BEARER_TOKEN"
	LeakTypeInternalIP   LeakType = "INTERNAL_IP_ADDRESS"
	LeakTypeImportMeta   LeakType = "IMPORT_META_LEAK"
	LeakTypeGenericSec   LeakType = "GENERIC_SECRET_KEY"
	LeakTypeAWSKey       LeakType = "AWS_ACCESS_KEY"
	LeakTypeStripeKey    LeakType = "STRIPE_SECRET_KEY"
	LeakTypeGitHubToken  LeakType = "GITHUB_PAT"
	LeakTypeSlackToken   LeakType = "SLACK_TOKEN"
	LeakTypeGitLabToken  LeakType = "GITLAB_PAT"
	LeakTypeSendGridKey  LeakType = "SENDGRID_API_KEY"
	LeakTypeMailgunKey   LeakType = "MAILGUN_API_KEY"
	LeakTypeResendKey    LeakType = "RESEND_API_KEY"
	LeakTypeTwilioKey    LeakType = "TWILIO_API_KEY"
	LeakTypeSquareToken  LeakType = "SQUARE_ACCESS_TOKEN"
	LeakTypeCloudflare   LeakType = "CLOUDFLARE_EXPOSED_CREDENTIAL"
	LeakTypeUserAPIToken LeakType = "USER_API_TOKEN"
	LeakTypeRSAPrivate     LeakType = "RSA_PRIVATE_KEY"
	LeakTypeFirebaseConfig LeakType = "FIREBASE_CONFIG_LEAK"
	LeakTypeSupabaseConfig LeakType = "SUPABASE_CONFIG_LEAK"
)

type Leak struct {
	LeakType     LeakType `json:"leak_type"`
	SourceURL    string   `json:"source_url"`
	GravityScore float64  `json:"gravity_score"`
	Snippet      string   `json:"snippet,omitempty"`
}

type TechInsight struct {
	Backend               string   `json:"backend,omitempty"`
	Frontend              string   `json:"frontend,omitempty"`
	Hosting               string   `json:"hosting,omitempty"`
	Server                string   `json:"server,omitempty"`
	CDNWAF                string   `json:"cdn_waf,omitempty"`
	CMS                   string   `json:"cms,omitempty"`
	Protocol              string   `json:"protocol,omitempty"`
	SPA                   string   `json:"spa,omitempty"`
	PWA                   string   `json:"pwa,omitempty"`
	ContentSecurityPolicy string   `json:"content_security_policy,omitempty"`
	XFrameOptions         string   `json:"x_frame_options,omitempty"`
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	AccessControlAllowOrigin string `json:"access_control_allow_origin,omitempty"`
	CookieSecurity         []string `json:"cookie_security,omitempty"`
	JWTIndicators          []string `json:"jwt_indicators,omitempty"`
	Routes                []string `json:"routes,omitempty"`
	ProbedRoutes          []string `json:"probed_routes,omitempty"`
	RobotsTxt             string   `json:"robots_txt,omitempty"`
	SitemapXML            string   `json:"sitemap_xml,omitempty"`
	APISpecs              []string `json:"api_specs,omitempty"`
	GraphQLIntrospection  string   `json:"graphql_introspection,omitempty"`
}
