package config

// Config is the top-level console configuration.
type Config struct {
	APIVersion    string `yaml:"apiVersion"`
	Kind          string `yaml:"kind"`
	ServingInfo   `yaml:"servingInfo"`
	ClusterInfo   `yaml:"clusterInfo"`
	Auth          `yaml:"auth"`
	Customization `yaml:"customization"`
	Providers     `yaml:"providers"`
}

// ServingInfo holds configuration for serving HTTP.
type ServingInfo struct {
	BindAddress string `yaml:"bindAddress"`
	CertFile    string `yaml:"certFile"`
	KeyFile     string `yaml:"keyFile"`

	// These fields are defined in `HTTPServingInfo`, but are not supported for console. Fail if any are specified.
	// https://github.com/openshift/api/blob/0cb4131a7636e1ada6b2769edc9118f0fe6844c8/config/v1/types.go#L7-L38
	BindNetwork           string        `yaml:"bindNetwork"`
	ClientCA              string        `yaml:"clientCA"`
	NamedCertificates     []interface{} `yaml:"namedCertificates"`
	MinTLSVersion         string        `yaml:"minTLSVersion"`
	CipherSuites          []string      `yaml:"cipherSuites"`
	MaxRequestsInFlight   int64         `yaml:"maxRequestsInFlight"`
	RequestTimeoutSeconds int64         `yaml:"requestTimeoutSeconds"`
}

// ClusterInfo holds information the about the cluster such as master public URL and console public URL.
type ClusterInfo struct {
	ConsoleBaseAddress string `yaml:"consoleBaseAddress"`
	ConsoleBasePath    string `yaml:"consoleBasePath"`
	MasterPublicURL    string `yaml:"masterPublicURL"`
}

// Auth holds configuration for authenticating with OpenShift. The auth method is assumed to be "openshift".
type Auth struct {
	ClientID            string `yaml:"clientID"`
	ClientSecretFile    string `yaml:"clientSecretFile"`
	OAuthEndpointCAFile string `yaml:"oauthEndpointCAFile"`
	LogoutRedirect      string `yaml:"logoutRedirect"`
}

// Customization holds configuration such as what logo to use.
type Customization struct {
	Branding             string `yaml:"branding"`
	DocumentationBaseURL string `yaml:"documentationBaseURL"`
	CustomProductName    string `yaml:"customProductName"`
	CustomLogoFile       string `yaml:"customLogoFile"`
}

type Providers struct {
	StatuspageID string `yaml:"statuspageID"`
}
