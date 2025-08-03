# qesctl - QES Platform CLI

`qesctl` is a command-line tool for configuring, managing, and deploying QES Platform installations. It provides an easy-to-use interface for setting up QES providers, managing tenants, and deploying the platform infrastructure.

## Features

- 🚀 **Easy Setup**: Initialize QES Platform configuration with guided setup
- 🔧 **Provider Management**: Configure QES providers (Freja eID, D-Trust, FNMT)
- 🏢 **Tenant Management**: Create and manage multi-tenant configurations
- 📋 **Configuration Validation**: Validate configuration files and settings
- 🚀 **Deployment**: Deploy QES Platform using Helm charts and Terraform
- 📊 **Status Monitoring**: Check platform and service status
- 🔍 **Testing**: Test provider connections and configurations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/qes-platform/qes-platform.git
cd qes-platform/tools/qesctl

# Build and install
make build
sudo mv qesctl /usr/local/bin/

# Or install directly
make install
```

### From Releases

Download the latest release for your platform from the [releases page](https://github.com/qes-platform/qes-platform/releases).

```bash
# Linux/macOS
curl -L https://github.com/qes-platform/qes-platform/releases/latest/download/qesctl-linux-amd64.tar.gz | tar xz
sudo mv qesctl /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/qes-platform/qes-platform/releases/latest/download/qesctl-windows-amd64.zip" -OutFile "qesctl.zip"
Expand-Archive qesctl.zip
Move-Item qesctl\qesctl.exe C:\Windows\System32\
```

### Using Docker

```bash
# Run qesctl in Docker
docker run --rm -it \
  -v ~/.qesctl:/root/.qesctl \
  qes-platform/qesctl:latest

# Create an alias for easier use
alias qesctl='docker run --rm -it -v ~/.qesctl:/root/.qesctl qes-platform/qesctl:latest'
```

## Quick Start

### 1. Initialize Configuration

```bash
# Interactive setup
qesctl init --interactive

# Or with a specific provider
qesctl init --provider freja-se --interactive

# Non-interactive (uses environment variables)
export QES_API_URL="https://api.qes-platform.com/v1"
export QES_TENANT_ID="your-tenant-id"
export QES_API_KEY="your-api-key"
qesctl init --provider freja-se
```

### 2. Configure QES Providers

```bash
# Configure Freja eID (Sweden)
qesctl provider configure freja-se --interactive

# Configure D-Trust (Germany)
qesctl provider configure dtrust-de --interactive

# Configure FNMT (Spain)
qesctl provider configure fnmt-es
```

### 3. Create Tenants

```bash
# Create a new tenant
qesctl tenant create \
  --name "My Company" \
  --subdomain "mycompany" \
  --tier "professional"

# List tenants
qesctl tenant list
```

### 4. Deploy Platform

```bash
# Deploy to development environment
qesctl deploy --environment development

# Deploy to production with dry-run first
qesctl deploy --environment production --dry-run
qesctl deploy --environment production
```

## Commands

### Global Options

- `--config`: Specify config file path (default: `~/.qesctl.yaml`)
- `--verbose, -v`: Enable verbose output
- `--format`: Output format (`yaml` or `json`)

### init

Initialize QES Platform configuration.

```bash
qesctl init [flags]

Flags:
  --provider string     QES provider to configure (freja-se, dtrust-de, fnmt-es)
  --interactive, -i     Interactive configuration
```

**Examples:**

```bash
# Interactive setup with provider configuration
qesctl init --provider freja-se --interactive

# Quick setup using environment variables
qesctl init --provider dtrust-de
```

### tenant

Manage tenants.

```bash
qesctl tenant [command]

Available Commands:
  create      Create a new tenant
  list        List all tenants
  configure   Configure tenant settings
```

**Examples:**

```bash
# Create a tenant
qesctl tenant create --name "ACME Corp" --subdomain "acme" --tier "enterprise"

# List all configured tenants
qesctl tenant list

# Configure tenant settings
qesctl tenant configure --subdomain "acme"
```

### provider

Manage QES providers.

```bash
qesctl provider [command]

Available Commands:
  configure   Configure a QES provider
  list        List configured providers
  test        Test provider connection
```

**Examples:**

```bash
# Configure provider interactively
qesctl provider configure freja-se --interactive

# List all providers
qesctl provider list

# Test provider connection
qesctl provider test freja-se
```

### deploy

Deploy QES Platform.

```bash
qesctl deploy [flags]

Flags:
  --environment string   Deployment environment (default "development")
  --kubeconfig string    Path to kubeconfig file
  --dry-run             Show what would be deployed without executing
```

**Examples:**

```bash
# Deploy to development
qesctl deploy --environment development

# Production deployment with dry-run
qesctl deploy --environment production --dry-run
qesctl deploy --environment production
```

### validate

Validate configuration files.

```bash
qesctl validate

# Validates:
# - Configuration file syntax
# - Required fields
# - Provider configurations
# - Tenant settings
```

### status

Show QES Platform status.

```bash
qesctl status

# Shows:
# - Configuration status
# - Configured providers
# - Tenant count
# - Service connectivity
```

### config

Manage configuration.

```bash
qesctl config [command]

Available Commands:
  view        View current configuration
  edit        Edit configuration file
```

**Examples:**

```bash
# View configuration (API key masked)
qesctl config view

# View as JSON
qesctl config view --format json

# Edit configuration in $EDITOR
qesctl config edit
```

## Configuration

### Configuration File

The configuration file is stored at `~/.qesctl/config.yaml` by default.

```yaml
api_url: https://api.qes-platform.com/v1
tenant_id: your-tenant-id
api_key: your-api-key

providers:
  freja-se:
    name: freja-se
    type: freja-eid
    country: SE
    environment: production
    enabled: true
    endpoints:
      oauth: https://services.frejaeid.com/oauth2
      scim: https://services.frejaeid.com/scim
    client_id: your-client-id
    client_secret: your-client-secret

  dtrust-de:
    name: dtrust-de
    type: dtrust
    country: DE
    environment: production
    enabled: true
    endpoints:
      eidas: https://www.d-trust.net/eidas
      signature: https://api.d-trust.net/qes
    client_cert_path: /path/to/client.crt
    client_key_path: /path/to/client.key

settings:
  default_signature_format: PAdES-LTA
  timeout: 30s
```

### Environment Variables

qesctl supports the following environment variables:

- `QES_API_URL`: QES Platform API URL
- `QES_TENANT_ID`: Tenant ID
- `QES_API_KEY`: API key
- `QES_CONFIG`: Path to config file
- `EDITOR`: Editor for config editing

### Tenant Configuration

Tenant configurations are stored in `~/.qesctl/tenants/`:

```yaml
# ~/.qesctl/tenants/mycompany.yaml
name: My Company
subdomain: mycompany
rate_limits:
  tier: professional
  signatures_per_hour: 100
  requests_per_hour: 1000
providers:
  - name: freja-se
    enabled: true
  - name: dtrust-de
    enabled: false
settings:
  rate_limiting_enabled: true
  audit_logging_enabled: true
```

## Provider Configuration

### Freja eID (Sweden)

```bash
qesctl provider configure freja-se --interactive
```

Required configuration:
- Client ID (OAuth2)
- Client Secret (OAuth2)
- Environment (test/production)

### D-Trust (Germany)

```bash
qesctl provider configure dtrust-de --interactive
```

Required configuration:
- Client certificate path
- Client key path
- Environment (test/production)

### FNMT (Spain)

```bash
qesctl provider configure fnmt-es
```

Basic configuration with default endpoints.

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/qes-platform/qes-platform.git
cd qes-platform/tools/qesctl

# Install dependencies
go mod download

# Build
make build

# Run tests
make test

# Cross-compile for all platforms
make cross-compile

# Create release packages
make package
```

### Project Structure

```
tools/qesctl/
├── main.go              # Main CLI application
├── go.mod              # Go module definition
├── go.sum              # Go module checksums
├── Makefile            # Build automation
├── README.md           # This file
├── Dockerfile          # Docker image
└── examples/           # Example configurations
    ├── basic-config.yaml
    ├── freja-config.yaml
    └── dtrust-config.yaml
```

### Adding New Commands

1. Create command function in `main.go`
2. Add command to appropriate parent command
3. Implement command logic
4. Add tests
5. Update documentation

Example:

```go
func newFeatureCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "new-feature",
        Short: "Description of new feature",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runNewFeature()
        },
    }
    
    return cmd
}

func runNewFeature() error {
    fmt.Println("Implementing new feature...")
    return nil
}
```

## Troubleshooting

### Common Issues

**Configuration not found:**
```bash
# Initialize configuration first
qesctl init --interactive
```

**Provider connection failed:**
```bash
# Check provider configuration
qesctl provider list
qesctl validate

# Test connection
qesctl provider test freja-se
```

**Deployment issues:**
```bash
# Validate configuration first
qesctl validate

# Use dry-run to see what would be deployed
qesctl deploy --dry-run

# Check platform status
qesctl status
```

### Debug Mode

Enable verbose output for debugging:

```bash
qesctl --verbose [command]
```

### Configuration Validation

Always validate configuration before deployment:

```bash
qesctl validate
```

## Examples

### Complete Setup Workflow

```bash
# 1. Initialize with Freja eID
qesctl init --provider freja-se --interactive

# 2. Create a tenant
qesctl tenant create \
  --name "ACME Corporation" \
  --subdomain "acme" \
  --tier "enterprise"

# 3. Configure additional provider
qesctl provider configure dtrust-de --interactive

# 4. Validate configuration
qesctl validate

# 5. Deploy to staging
qesctl deploy --environment staging

# 6. Check status
qesctl status
```

### Configuration Management

```bash
# View current configuration
qesctl config view

# Edit configuration
qesctl config edit

# List all providers
qesctl provider list

# Test provider connections
qesctl provider test freja-se
qesctl provider test dtrust-de
```

### Multi-Environment Deployment

```bash
# Development
qesctl deploy --environment development

# Staging
qesctl deploy --environment staging --dry-run
qesctl deploy --environment staging

# Production
qesctl deploy --environment production --dry-run
qesctl deploy --environment production
```

## Support

- 📖 **Documentation**: [docs.qes-platform.com](https://docs.qes-platform.com)
- 🐛 **Issues**: [GitHub Issues](https://github.com/qes-platform/qes-platform/issues)
- 💬 **Community**: [Discord](https://discord.gg/qes-platform)
- 📧 **Support**: [support@qes-platform.com](mailto:support@qes-platform.com)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.