package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	"gopkg.in/yaml.v2"
)

// QESConfig represents the QES Platform configuration
type QESConfig struct {
	APIUrl    string            `yaml:"api_url" json:"api_url"`
	TenantID  string            `yaml:"tenant_id" json:"tenant_id"`
	APIKey    string            `yaml:"api_key" json:"api_key"`
	Providers map[string]interface{} `yaml:"providers" json:"providers"`
	Settings  map[string]interface{} `yaml:"settings" json:"settings"`
}

// TenantConfig represents tenant-specific configuration
type TenantConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Subdomain   string                 `yaml:"subdomain" json:"subdomain"`
	RateLimits  map[string]interface{} `yaml:"rate_limits" json:"rate_limits"`
	Providers   []ProviderConfig       `yaml:"providers" json:"providers"`
	Settings    map[string]interface{} `yaml:"settings" json:"settings"`
}

// ProviderConfig represents QES provider configuration
type ProviderConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        string                 `yaml:"type" json:"type"`
	Country     string                 `yaml:"country" json:"country"`
	Environment string                 `yaml:"environment" json:"environment"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
}

var (
	configFile string
	verbose    bool
	format     string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "qesctl",
		Short: "QES Platform Configuration CLI",
		Long: `qesctl is a command-line tool for configuring and managing
QES Platform installations, tenants, and providers.

Examples:
  qesctl init --provider freja-se
  qesctl tenant create --name "My Company" --subdomain mycompany
  qesctl provider configure freja-se
  qesctl deploy --environment production`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.qesctl.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&format, "format", "yaml", "output format (yaml|json)")

	// Add subcommands
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(tenantCmd())
	rootCmd.AddCommand(providerCmd())
	rootCmd.AddCommand(deployCmd())
	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(configCmd())

	// Initialize configuration
	cobra.OnInitialize(initConfig)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func initConfig() {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".qesctl")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("QES")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	}
}

func initCmd() *cobra.Command {
	var provider string
	var interactive bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize QES Platform configuration",
		Long: `Initialize a new QES Platform configuration with basic settings
and optionally configure a QES provider.

This command creates a configuration file and sets up initial settings
for connecting to the QES Platform API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(provider, interactive)
		},
	}

	cmd.Flags().StringVar(&provider, "provider", "", "QES provider to configure (freja-se, dtrust-de, fnmt-es)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive configuration")

	return cmd
}

func runInit(provider string, interactive bool) error {
	fmt.Println("🚀 Initializing QES Platform Configuration")
	fmt.Println("=" + strings.Repeat("=", 45))

	config := &QESConfig{
		Providers: make(map[string]interface{}),
		Settings:  make(map[string]interface{}),
	}

	// Get basic configuration
	if interactive {
		if err := promptBasicConfig(config); err != nil {
			return fmt.Errorf("failed to get basic configuration: %w", err)
		}
	} else {
		config.APIUrl = getEnvOrDefault("QES_API_URL", "https://api.qes-platform.com/v1")
		config.TenantID = getEnvOrDefault("QES_TENANT_ID", "")
		config.APIKey = getEnvOrDefault("QES_API_KEY", "")
	}

	// Configure provider if specified
	if provider != "" {
		fmt.Printf("\n🔧 Configuring %s provider...\n", provider)
		if err := configureProvider(config, provider, interactive); err != nil {
			return fmt.Errorf("failed to configure provider: %w", err)
		}
	}

	// Save configuration
	if err := saveConfig(config); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Println("\n✅ Configuration initialized successfully!")
	
	if provider != "" {
		fmt.Printf("📋 Next steps for %s:\n", provider)
		printProviderNextSteps(provider)
	} else {
		fmt.Println("📋 Next steps:")
		fmt.Println("   • Configure a QES provider: qesctl provider configure <provider>")
		fmt.Println("   • Create a tenant: qesctl tenant create")
		fmt.Println("   • Deploy: qesctl deploy")
	}

	return nil
}

func promptBasicConfig(config *QESConfig) error {
	reader := bufio.NewReader(os.Stdin)

	// API URL
	fmt.Print("QES Platform API URL [https://api.qes-platform.com/v1]: ")
	apiUrl, _ := reader.ReadString('\n')
	apiUrl = strings.TrimSpace(apiUrl)
	if apiUrl == "" {
		apiUrl = "https://api.qes-platform.com/v1"
	}
	config.APIUrl = apiUrl

	// Tenant ID
	fmt.Print("Tenant ID: ")
	tenantId, _ := reader.ReadString('\n')
	config.TenantID = strings.TrimSpace(tenantId)

	// API Key (hidden input)
	fmt.Print("API Key: ")
	apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read API key: %w", err)
	}
	fmt.Println() // New line after password input
	config.APIKey = string(apiKeyBytes)

	return nil
}

func configureProvider(config *QESConfig, provider string, interactive bool) error {
	switch provider {
	case "freja-se":
		return configureFrejaProvider(config, interactive)
	case "dtrust-de":
		return configureDTrustProvider(config, interactive)
	case "fnmt-es":
		return configureFNMTProvider(config, interactive)
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}
}

func configureFrejaProvider(config *QESConfig, interactive bool) error {
	frejaConfig := map[string]interface{}{
		"name":        "freja-se",
		"type":        "freja-eid",
		"country":     "SE",
		"environment": "test",
		"enabled":     true,
		"endpoints": map[string]string{
			"oauth": "https://services.test.frejaeid.com/oauth2",
			"scim":  "https://services.test.frejaeid.com/scim",
		},
	}

	if interactive {
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Environment (test/production) [test]: ")
		env, _ := reader.ReadString('\n')
		env = strings.TrimSpace(env)
		if env == "" {
			env = "test"
		}
		frejaConfig["environment"] = env

		if env == "production" {
			frejaConfig["endpoints"] = map[string]string{
				"oauth": "https://services.frejaeid.com/oauth2",
				"scim":  "https://services.frejaeid.com/scim",
			}
		}

		fmt.Print("Client ID: ")
		clientId, _ := reader.ReadString('\n')
		frejaConfig["client_id"] = strings.TrimSpace(clientId)

		fmt.Print("Client Secret: ")
		clientSecretBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read client secret: %w", err)
		}
		fmt.Println()
		frejaConfig["client_secret"] = string(clientSecretBytes)
	}

	config.Providers["freja-se"] = frejaConfig
	return nil
}

func configureDTrustProvider(config *QESConfig, interactive bool) error {
	dtrustConfig := map[string]interface{}{
		"name":        "dtrust-de",
		"type":        "dtrust",
		"country":     "DE",
		"environment": "test",
		"enabled":     true,
		"endpoints": map[string]string{
			"eidas":     "https://www.d-trust.net/eidas",
			"signature": "https://api.d-trust.net/qes",
		},
	}

	if interactive {
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Environment (test/production) [test]: ")
		env, _ := reader.ReadString('\n')
		env = strings.TrimSpace(env)
		if env == "" {
			env = "test"
		}
		dtrustConfig["environment"] = env

		fmt.Print("Client Certificate Path: ")
		certPath, _ := reader.ReadString('\n')
		dtrustConfig["client_cert_path"] = strings.TrimSpace(certPath)

		fmt.Print("Client Key Path: ")
		keyPath, _ := reader.ReadString('\n')
		dtrustConfig["client_key_path"] = strings.TrimSpace(keyPath)
	}

	config.Providers["dtrust-de"] = dtrustConfig
	return nil
}

func configureFNMTProvider(config *QESConfig, interactive bool) error {
	fnmtConfig := map[string]interface{}{
		"name":        "fnmt-es",
		"type":        "fnmt",
		"country":     "ES",
		"environment": "test",
		"enabled":     true,
		"endpoints": map[string]string{
			"auth": "https://www.sede.fnmt.gob.es/",
		},
	}

	config.Providers["fnmt-es"] = fnmtConfig
	return nil
}

func saveConfig(config *QESConfig) error {
	configDir := filepath.Join(os.Getenv("HOME"), ".qesctl")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("💾 Configuration saved to: %s\n", configPath)
	return nil
}

func printProviderNextSteps(provider string) {
	switch provider {
	case "freja-se":
		fmt.Println("   1. Register your application with Freja eID")
		fmt.Println("   2. Obtain OAuth2 client credentials")
		fmt.Println("   3. Configure your client ID and secret")
		fmt.Println("   4. Test authentication in sandbox environment")
		fmt.Println("   📖 Guide: https://docs.qes-platform.com/providers/freja")
	case "dtrust-de":
		fmt.Println("   1. Register with D-Trust for QES services")
		fmt.Println("   2. Obtain client certificates")
		fmt.Println("   3. Configure certificate paths")
		fmt.Println("   4. Test eIDAS authentication flow")
		fmt.Println("   📖 Guide: https://docs.qes-platform.com/providers/dtrust")
	case "fnmt-es":
		fmt.Println("   1. Register with FNMT for QES services")
		fmt.Println("   2. Configure authentication endpoints")
		fmt.Println("   3. Test signature creation")
		fmt.Println("   📖 Guide: https://docs.qes-platform.com/providers/fnmt")
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func tenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Manage tenants",
		Long:  "Create, configure, and manage QES Platform tenants",
	}

	cmd.AddCommand(tenantCreateCmd())
	cmd.AddCommand(tenantListCmd())
	cmd.AddCommand(tenantConfigureCmd())

	return cmd
}

func tenantCreateCmd() *cobra.Command {
	var name, subdomain string
	var tier string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTenantCreate(name, subdomain, tier)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Tenant name (required)")
	cmd.Flags().StringVar(&subdomain, "subdomain", "", "Tenant subdomain (required)")
	cmd.Flags().StringVar(&tier, "tier", "professional", "Tenant tier (free, professional, enterprise)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("subdomain")

	return cmd
}

func runTenantCreate(name, subdomain, tier string) error {
	fmt.Printf("🏢 Creating tenant: %s\n", name)

	tenant := TenantConfig{
		Name:      name,
		Subdomain: subdomain,
		RateLimits: map[string]interface{}{
			"tier": tier,
		},
		Providers: []ProviderConfig{},
		Settings: map[string]interface{}{
			"rate_limiting_enabled": true,
			"audit_logging_enabled": true,
		},
	}

	// Save tenant configuration
	tenantPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "tenants", subdomain+".yaml")
	if err := os.MkdirAll(filepath.Dir(tenantPath), 0755); err != nil {
		return fmt.Errorf("failed to create tenant directory: %w", err)
	}

	data, err := yaml.Marshal(tenant)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant config: %w", err)
	}

	if err := ioutil.WriteFile(tenantPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write tenant config: %w", err)
	}

	fmt.Printf("✅ Tenant '%s' created successfully!\n", name)
	fmt.Printf("📁 Configuration saved to: %s\n", tenantPath)
	fmt.Printf("🌐 Subdomain: %s.qes-platform.com\n", subdomain)
	fmt.Printf("📊 Tier: %s\n", tier)

	return nil
}

func tenantListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tenants",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTenantList()
		},
	}
}

func runTenantList() error {
	tenantDir := filepath.Join(os.Getenv("HOME"), ".qesctl", "tenants")
	
	files, err := ioutil.ReadDir(tenantDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No tenants found. Create one with 'qesctl tenant create'")
			return nil
		}
		return fmt.Errorf("failed to read tenant directory: %w", err)
	}

	fmt.Println("🏢 Configured Tenants:")
	fmt.Println("=" + strings.Repeat("=", 20))

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}

		tenantPath := filepath.Join(tenantDir, file.Name())
		data, err := ioutil.ReadFile(tenantPath)
		if err != nil {
			continue
		}

		var tenant TenantConfig
		if err := yaml.Unmarshal(data, &tenant); err != nil {
			continue
		}

		fmt.Printf("📋 %s\n", tenant.Name)
		fmt.Printf("   Subdomain: %s\n", tenant.Subdomain)
		fmt.Printf("   Providers: %d configured\n", len(tenant.Providers))
		if tier, ok := tenant.RateLimits["tier"].(string); ok {
			fmt.Printf("   Tier: %s\n", tier)
		}
		fmt.Println()
	}

	return nil
}

func tenantConfigureCmd() *cobra.Command {
	var subdomain string

	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure tenant settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTenantConfigure(subdomain)
		},
	}

	cmd.Flags().StringVar(&subdomain, "subdomain", "", "Tenant subdomain (required)")
	cmd.MarkFlagRequired("subdomain")

	return cmd
}

func runTenantConfigure(subdomain string) error {
	fmt.Printf("⚙️  Configuring tenant: %s\n", subdomain)
	// Implementation for tenant configuration
	return nil
}

func providerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "Manage QES providers",
		Long:  "Configure and manage QES provider integrations",
	}

	cmd.AddCommand(providerConfigureCmd())
	cmd.AddCommand(providerListCmd())
	cmd.AddCommand(providerTestCmd())

	return cmd
}

func providerConfigureCmd() *cobra.Command {
	var interactive bool

	cmd := &cobra.Command{
		Use:   "configure [provider]",
		Short: "Configure a QES provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProviderConfigure(args[0], interactive)
		},
	}

	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive configuration")

	return cmd
}

func runProviderConfigure(provider string, interactive bool) error {
	fmt.Printf("🔧 Configuring provider: %s\n", provider)

	// Load existing config
	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	var config QESConfig

	if data, err := ioutil.ReadFile(configPath); err == nil {
		yaml.Unmarshal(data, &config)
	}

	if config.Providers == nil {
		config.Providers = make(map[string]interface{})
	}

	// Configure the provider
	if err := configureProvider(&config, provider, interactive); err != nil {
		return err
	}

	// Save updated config
	return saveConfig(&config)
}

func providerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProviderList()
		},
	}
}

func runProviderList() error {
	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("No configuration found. Run 'qesctl init' first.")
		return nil
	}

	var config QESConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	fmt.Println("🔧 Configured Providers:")
	fmt.Println("=" + strings.Repeat("=", 25))

	if len(config.Providers) == 0 {
		fmt.Println("No providers configured. Use 'qesctl provider configure <provider>' to add one.")
		return nil
	}

	for name, providerConfig := range config.Providers {
		fmt.Printf("📋 %s\n", name)
		if pc, ok := providerConfig.(map[string]interface{}); ok {
			if country, ok := pc["country"].(string); ok {
				fmt.Printf("   Country: %s\n", country)
			}
			if env, ok := pc["environment"].(string); ok {
				fmt.Printf("   Environment: %s\n", env)
			}
			if enabled, ok := pc["enabled"].(bool); ok {
				status := "❌ Disabled"
				if enabled {
					status = "✅ Enabled"
				}
				fmt.Printf("   Status: %s\n", status)
			}
		}
		fmt.Println()
	}

	return nil
}

func providerTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test [provider]",
		Short: "Test provider connection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProviderTest(args[0])
		},
	}

	return cmd
}

func runProviderTest(provider string) error {
	fmt.Printf("🧪 Testing provider: %s\n", provider)
	fmt.Println("This would test the provider connection...")
	// Implementation for provider testing
	return nil
}

func deployCmd() *cobra.Command {
	var environment, kubeconfig string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy QES Platform",
		Long:  "Deploy QES Platform using Helm charts and Terraform",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeploy(environment, kubeconfig, dryRun)
		},
	}

	cmd.Flags().StringVar(&environment, "environment", "development", "deployment environment")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be deployed without executing")

	return cmd
}

func runDeploy(environment, kubeconfig string, dryRun bool) error {
	fmt.Printf("🚀 Deploying QES Platform to %s environment\n", environment)

	if dryRun {
		fmt.Println("🔍 Dry run mode - showing what would be deployed:")
		fmt.Println("   • PostgreSQL database")
		fmt.Println("   • Redis cache")
		fmt.Println("   • HashiCorp Vault")
		fmt.Println("   • QES Platform API")
		fmt.Println("   • Monitoring stack (Prometheus, Grafana, Loki)")
		return nil
	}

	fmt.Println("This would deploy the platform using Helm charts...")
	// Implementation for deployment
	return nil
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		Long:  "Validate QES Platform configuration files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate()
		},
	}
}

func runValidate() error {
	fmt.Println("🔍 Validating configuration...")

	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("configuration file not found: %w", err)
	}

	var config QESConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid YAML configuration: %w", err)
	}

	// Validate basic configuration
	if config.APIUrl == "" {
		fmt.Println("❌ API URL is not configured")
	} else {
		fmt.Printf("✅ API URL: %s\n", config.APIUrl)
	}

	if config.TenantID == "" {
		fmt.Println("❌ Tenant ID is not configured")
	} else {
		fmt.Printf("✅ Tenant ID: %s\n", config.TenantID)
	}

	if config.APIKey == "" {
		fmt.Println("❌ API Key is not configured")
	} else {
		fmt.Println("✅ API Key is configured")
	}

	// Validate providers
	fmt.Printf("📋 Providers configured: %d\n", len(config.Providers))
	for name, provider := range config.Providers {
		if pc, ok := provider.(map[string]interface{}); ok {
			if enabled, ok := pc["enabled"].(bool); ok && enabled {
				fmt.Printf("✅ Provider %s is enabled\n", name)
			} else {
				fmt.Printf("⚠️  Provider %s is disabled\n", name)
			}
		}
	}

	fmt.Println("✅ Configuration validation completed")
	return nil
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show QES Platform status",
		Long:  "Display status information about QES Platform deployment and services",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus()
		},
	}
}

func runStatus() error {
	fmt.Println("📊 QES Platform Status")
	fmt.Println("=" + strings.Repeat("=", 25))

	// Check configuration
	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("✅ Configuration file exists")
	} else {
		fmt.Println("❌ Configuration file not found")
		fmt.Println("   Run 'qesctl init' to create configuration")
		return nil
	}

	// Load and display config status
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var config QESConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	fmt.Printf("🌐 API URL: %s\n", config.APIUrl)
	fmt.Printf("🏢 Tenant ID: %s\n", config.TenantID)
	fmt.Printf("🔧 Providers: %d configured\n", len(config.Providers))

	// Check tenant configurations
	tenantDir := filepath.Join(os.Getenv("HOME"), ".qesctl", "tenants")
	if files, err := ioutil.ReadDir(tenantDir); err == nil {
		fmt.Printf("🏢 Tenants: %d configured\n", len(files))
	} else {
		fmt.Println("🏢 Tenants: 0 configured")
	}

	fmt.Println("\n📋 Service Status:")
	fmt.Println("   🔍 API connectivity: Not checked (use 'qesctl provider test')")
	fmt.Println("   🔧 Providers: Not tested (use 'qesctl provider test <provider>')")
	fmt.Println("   🚀 Deployment: Not checked (use 'qesctl deploy --dry-run')")

	return nil
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
		Long:  "View and edit QES Platform configuration",
	}

	cmd.AddCommand(configViewCmd())
	cmd.AddCommand(configEditCmd())

	return cmd
}

func configViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "View current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigView()
		},
	}
}

func runConfigView() error {
	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("configuration file not found: %w", err)
	}

	if format == "json" {
		var config QESConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}

		// Mask sensitive data
		if config.APIKey != "" {
			config.APIKey = "***masked***"
		}

		jsonData, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal to JSON: %w", err)
		}

		fmt.Println(string(jsonData))
	} else {
		// Mask API key in YAML output
		content := string(data)
		if strings.Contains(content, "api_key:") {
			lines := strings.Split(content, "\n")
			for i, line := range lines {
				if strings.Contains(line, "api_key:") {
					lines[i] = "api_key: ***masked***"
				}
			}
			content = strings.Join(lines, "\n")
		}

		fmt.Println(content)
	}

	return nil
}

func configEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigEdit()
		},
	}
}

func runConfigEdit() error {
	configPath := filepath.Join(os.Getenv("HOME"), ".qesctl", "config.yaml")
	
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim" // Default to vim
	}

	fmt.Printf("📝 Opening configuration in %s...\n", editor)
	fmt.Printf("File: %s\n", configPath)
	
	// This would open the editor (simplified for demo)
	fmt.Println("(Editor would open here)")
	
	return nil
}