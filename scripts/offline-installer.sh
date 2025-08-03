#!/bin/bash
# QES Platform Offline Installer
# Creates an air-gapped deployment package for environments without internet access

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INSTALLER_DIR="$PROJECT_ROOT/installer"
PACKAGE_NAME="qes-platform-offline"
VERSION="${VERSION:-1.0.0}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PACKAGE_DIR="$INSTALLER_DIR/${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}"

echo "🚀 QES Platform Offline Installer Builder"
echo "=========================================="
echo "Version: $VERSION"
echo "Build time: $(date)"
echo "Package: $PACKAGE_NAME-$VERSION-$TIMESTAMP"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    
    local required_tools=("docker" "helm" "kubectl" "skopeo")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "❌ Required tool not found: $tool"
            echo "Please install $tool and try again."
            exit 1
        else
            echo "✅ Found: $tool"
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        echo "❌ Docker daemon is not running"
        echo "Please start Docker and try again."
        exit 1
    fi
    
    echo "✅ All prerequisites met"
}

# Function to create package directory structure
create_package_structure() {
    echo "📁 Creating package structure..."
    
    mkdir -p "$PACKAGE_DIR"/{images,charts,config,scripts,docs}
    
    cat > "$PACKAGE_DIR/README.md" << 'EOF'
# QES Platform Offline Installation Package

This package contains everything needed to deploy QES Platform in an air-gapped environment.

## Contents

- `images/` - Container images as tar files
- `charts/` - Helm charts
- `config/` - Configuration files and examples
- `scripts/` - Installation and management scripts
- `docs/` - Documentation

## Quick Start

1. Load container images:
   ```bash
   ./scripts/load-images.sh
   ```

2. Install with Helm:
   ```bash
   ./scripts/install.sh
   ```

3. Verify installation:
   ```bash
   ./scripts/verify.sh
   ```

For detailed instructions, see docs/INSTALLATION.md
EOF
    
    echo "✅ Package structure created"
}

# Function to export container images
export_container_images() {
    echo "🐳 Exporting container images..."
    
    # Define images to export
    local images=(
        # Core platform images
        "qes-platform/backend:$VERSION"
        "qes-platform/frontend:$VERSION"
        "qes-platform/softhsm:$VERSION"
        
        # Dependencies
        "postgres:15"
        "redis:7-alpine"
        "vault:1.14"
        "grafana/grafana:10.0.0"
        "prom/prometheus:v2.45.0"
        "grafana/loki:2.8.0"
        "minio/minio:RELEASE.2023-07-07T07-13-57Z"
        
        # Monitoring
        "grafana/promtail:2.8.0"
        "jaegertracing/all-in-one:1.46"
        
        # Tools
        "nginx:1.25-alpine"
        "alpine:3.18"
    )
    
    # Build core images if they don't exist
    build_core_images
    
    # Export each image
    for image in "${images[@]}"; do
        echo "📦 Exporting $image..."
        
        local filename
        filename="$(echo "$image" | tr '/:' '_')"
        
        # Pull image if not local
        if ! docker image inspect "$image" &> /dev/null; then
            echo "   Pulling $image..."
            docker pull "$image"
        fi
        
        # Save image
        docker save "$image" | gzip > "$PACKAGE_DIR/images/${filename}.tar.gz"
        echo "   ✅ Saved as ${filename}.tar.gz"
    done
    
    # Create image list
    printf '%s\n' "${images[@]}" > "$PACKAGE_DIR/images/image-list.txt"
    
    echo "✅ Container images exported"
}

# Function to build core platform images
build_core_images() {
    echo "🔨 Building core platform images..."
    
    cd "$PROJECT_ROOT"
    
    # Build backend image
    echo "   Building backend image..."
    docker build -t "qes-platform/backend:$VERSION" backend/
    
    # Build frontend image if exists
    if [ -d "ui/" ]; then
        echo "   Building frontend image..."
        docker build -t "qes-platform/frontend:$VERSION" ui/
    fi
    
    # Build SoftHSM image
    echo "   Building SoftHSM image..."
    docker build -t "qes-platform/softhsm:$VERSION" -f quickstart/Dockerfile.softhsm quickstart/
    
    echo "✅ Core images built"
}

# Function to package Helm charts
package_helm_charts() {
    echo "📊 Packaging Helm charts..."
    
    cd "$PROJECT_ROOT"
    
    # Package main chart
    helm package charts/qes-platform -d "$PACKAGE_DIR/charts/"
    
    # Package dependency charts
    local deps=(
        "postgresql"
        "redis" 
        "vault"
        "grafana"
        "prometheus"
        "loki"
    )
    
    for dep in "${deps[@]}"; do
        echo "   Packaging $dep chart..."
        helm repo add bitnami https://charts.bitnami.com/bitnami &> /dev/null || true
        helm repo add hashicorp https://helm.releases.hashicorp.com &> /dev/null || true
        helm repo add grafana https://grafana.github.io/helm-charts &> /dev/null || true
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts &> /dev/null || true
        helm repo update &> /dev/null
        
        # Download dependency chart
        case $dep in
            "postgresql"|"redis")
                helm pull bitnami/$dep --untar -d "$PACKAGE_DIR/charts/"
                ;;
            "vault")
                helm pull hashicorp/$dep --untar -d "$PACKAGE_DIR/charts/"
                ;;
            "grafana"|"loki")
                helm pull grafana/$dep --untar -d "$PACKAGE_DIR/charts/"
                ;;
            "prometheus")
                helm pull prometheus-community/$dep --untar -d "$PACKAGE_DIR/charts/"
                ;;
        esac
    done
    
    echo "✅ Helm charts packaged"
}

# Function to create configuration files
create_config_files() {
    echo "⚙️  Creating configuration files..."
    
    # Copy values files
    cp -r "$PROJECT_ROOT/charts/qes-platform/values"* "$PACKAGE_DIR/config/"
    
    # Create offline values overlay
    cat > "$PACKAGE_DIR/config/values-offline.yaml" << 'EOF'
# Offline deployment values for QES Platform
# These values override defaults for air-gapped installations

global:
  imageRegistry: "localhost:5000"  # Local registry
  imagePullSecrets: []

# Disable external dependencies
postgresql:
  enabled: true
  image:
    registry: "localhost:5000"
    
redis:
  enabled: true
  image:
    registry: "localhost:5000"

vault:
  enabled: true
  server:
    image:
      registry: "localhost:5000"

# External services configuration for offline
externalServices:
  timestampAuthority:
    external: false
    mock:
      enabled: true
  
  hsm:
    type: "softhsm"
    softhsm:
      enabled: true
      image:
        repository: "localhost:5000/qes-platform/softhsm"

# Provider configurations for offline testing
providers:
  frejaId:
    enabled: false  # Disable external providers
  dtrust:
    enabled: false
  fnmt:
    enabled: false

# Development/demo mode
development:
  mockServices:
    enabled: true
  sampleData:
    enabled: true
EOF

    # Create environment-specific configs
    for env in "development" "staging" "production"; do
        cp "$PACKAGE_DIR/config/values-offline.yaml" "$PACKAGE_DIR/config/values-$env-offline.yaml"
    done
    
    # Copy quickstart configs
    cp -r "$PROJECT_ROOT/quickstart" "$PACKAGE_DIR/config/"
    
    echo "✅ Configuration files created"
}

# Function to create installation scripts
create_installation_scripts() {
    echo "📜 Creating installation scripts..."
    
    # Image loader script
    cat > "$PACKAGE_DIR/scripts/load-images.sh" << 'EOF'
#!/bin/bash
# Load container images into local Docker daemon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$(dirname "$SCRIPT_DIR")/images"

echo "🐳 Loading container images..."

if [ ! -f "$IMAGES_DIR/image-list.txt" ]; then
    echo "❌ Image list not found"
    exit 1
fi

while IFS= read -r image; do
    if [ -n "$image" ]; then
        filename="$(echo "$image" | tr '/:' '_')"
        image_file="$IMAGES_DIR/${filename}.tar.gz"
        
        if [ -f "$image_file" ]; then
            echo "📦 Loading $image..."
            gunzip -c "$image_file" | docker load
        else
            echo "⚠️  Image file not found: $image_file"
        fi
    fi
done < "$IMAGES_DIR/image-list.txt"

echo "✅ All images loaded"
EOF

    # Main installer script
    cat > "$PACKAGE_DIR/scripts/install.sh" << 'EOF'
#!/bin/bash
# QES Platform Offline Installer

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
CHARTS_DIR="$PACKAGE_DIR/charts"
CONFIG_DIR="$PACKAGE_DIR/config"

# Default values
NAMESPACE="qes-platform"
RELEASE_NAME="qes-platform"
ENVIRONMENT="development"
VALUES_FILE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -r|--release)
            RELEASE_NAME="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -f|--values)
            VALUES_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -n, --namespace   Kubernetes namespace (default: qes-platform)"
            echo "  -r, --release     Helm release name (default: qes-platform)"
            echo "  -e, --environment Environment (development|staging|production)"
            echo "  -f, --values      Custom values file"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "🚀 Installing QES Platform (Offline)"
echo "===================================="
echo "Namespace: $NAMESPACE"
echo "Release: $RELEASE_NAME"
echo "Environment: $ENVIRONMENT"
echo ""

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found"
    exit 1
fi

if ! command -v helm &> /dev/null; then
    echo "❌ helm not found"
    exit 1
fi

# Create namespace
echo "📁 Creating namespace..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Determine values file
if [ -z "$VALUES_FILE" ]; then
    VALUES_FILE="$CONFIG_DIR/values-$ENVIRONMENT-offline.yaml"
fi

if [ ! -f "$VALUES_FILE" ]; then
    echo "❌ Values file not found: $VALUES_FILE"
    exit 1
fi

# Install with Helm
echo "📊 Installing with Helm..."
helm upgrade --install "$RELEASE_NAME" "$CHARTS_DIR/qes-platform" \
    --namespace "$NAMESPACE" \
    --values "$VALUES_FILE" \
    --wait \
    --timeout 10m

echo ""
echo "✅ QES Platform installed successfully!"
echo ""
echo "Next steps:"
echo "1. Wait for all pods to be ready:"
echo "   kubectl get pods -n $NAMESPACE"
echo ""
echo "2. Get access credentials:"
echo "   kubectl get secret -n $NAMESPACE ${RELEASE_NAME}-admin-credentials -o yaml"
echo ""
echo "3. Port-forward to access:"
echo "   kubectl port-forward -n $NAMESPACE svc/${RELEASE_NAME}-api 8000:8000"
echo "   kubectl port-forward -n $NAMESPACE svc/${RELEASE_NAME}-ui 3000:3000"
EOF

    # Verification script
    cat > "$PACKAGE_DIR/scripts/verify.sh" << 'EOF'
#!/bin/bash
# Verify QES Platform installation

set -e

NAMESPACE="${1:-qes-platform}"
RELEASE_NAME="${2:-qes-platform}"

echo "🔍 Verifying QES Platform installation..."
echo "Namespace: $NAMESPACE"
echo "Release: $RELEASE_NAME"
echo ""

# Check Helm release
echo "📊 Checking Helm release..."
if helm status "$RELEASE_NAME" -n "$NAMESPACE" &> /dev/null; then
    echo "✅ Helm release found"
    helm status "$RELEASE_NAME" -n "$NAMESPACE"
else
    echo "❌ Helm release not found"
    exit 1
fi

echo ""

# Check pods
echo "🐳 Checking pods..."
kubectl get pods -n "$NAMESPACE" -o wide

echo ""

# Check services
echo "🌐 Checking services..."
kubectl get services -n "$NAMESPACE"

echo ""

# Health checks
echo "🏥 Running health checks..."

# API health
if kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=qes-platform-api -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
    echo "✅ API pod is running"
else
    echo "❌ API pod is not running"
fi

# Database connectivity
if kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=postgresql -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
    echo "✅ Database is running"
else
    echo "❌ Database is not running"
fi

# Redis connectivity  
if kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
    echo "✅ Redis is running"
else
    echo "❌ Redis is not running"
fi

echo ""
echo "✅ Verification complete"
EOF

    # Uninstall script
    cat > "$PACKAGE_DIR/scripts/uninstall.sh" << 'EOF'
#!/bin/bash
# Uninstall QES Platform

set -e

NAMESPACE="${1:-qes-platform}"
RELEASE_NAME="${2:-qes-platform}"

echo "🗑️  Uninstalling QES Platform..."
echo "Namespace: $NAMESPACE"
echo "Release: $RELEASE_NAME"
echo ""

# Confirm uninstall
read -p "Are you sure you want to uninstall QES Platform? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled"
    exit 0
fi

# Uninstall Helm release
echo "📊 Uninstalling Helm release..."
helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true

# Delete PVCs (optional)
read -p "Delete persistent volumes and data? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️  Deleting PVCs..."
    kubectl delete pvc -n "$NAMESPACE" --all || true
fi

# Delete namespace
read -p "Delete namespace $NAMESPACE? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️  Deleting namespace..."
    kubectl delete namespace "$NAMESPACE" || true
fi

echo "✅ Uninstall complete"
EOF

    # Make scripts executable
    chmod +x "$PACKAGE_DIR/scripts"/*.sh
    
    echo "✅ Installation scripts created"
}

# Function to create documentation
create_documentation() {
    echo "📚 Creating documentation..."
    
    # Installation guide
    cat > "$PACKAGE_DIR/docs/INSTALLATION.md" << 'EOF'
# QES Platform Offline Installation Guide

This guide covers installing QES Platform in an air-gapped environment.

## Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3.8+
- kubectl configured for your cluster
- At least 16GB RAM and 4 CPU cores
- 100GB available storage

## Installation Steps

### 1. Load Container Images

First, load all required container images:

```bash
./scripts/load-images.sh
```

This will load all images from the `images/` directory into your local Docker daemon.

### 2. Configure Installation

Choose your environment and review the configuration:

```bash
# For development
cp config/values-development-offline.yaml config/my-values.yaml

# For production
cp config/values-production-offline.yaml config/my-values.yaml
```

Edit `config/my-values.yaml` to match your environment.

### 3. Install QES Platform

Run the installation script:

```bash
# Development environment
./scripts/install.sh -e development

# Production environment  
./scripts/install.sh -e production -f config/my-values.yaml
```

### 4. Verify Installation

Check that everything is running:

```bash
./scripts/verify.sh
```

### 5. Access the Platform

Port-forward to access the services:

```bash
# API
kubectl port-forward -n qes-platform svc/qes-platform-api 8000:8000

# UI (if available)
kubectl port-forward -n qes-platform svc/qes-platform-ui 3000:3000
```

Access the platform at http://localhost:8000

## Configuration

### Environment Variables

Key environment variables can be set in your values file:

```yaml
api:
  env:
    - name: LOG_LEVEL
      value: "INFO"
    - name: ENVIRONMENT
      value: "production"
```

### Persistent Storage

Configure storage classes for your environment:

```yaml
global:
  storageClass: "local-storage"

postgresql:
  primary:
    persistence:
      storageClass: "local-storage"
      size: "50Gi"
```

### Networking

For production deployments, configure ingress:

```yaml
api:
  ingress:
    enabled: true
    className: "nginx"
    hosts:
      - host: qes.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
```

## Troubleshooting

### Common Issues

**Pods stuck in Pending state:**
- Check resource requirements
- Verify storage classes
- Check node selectors

**Database connection errors:**
- Verify PostgreSQL pod is running
- Check database credentials
- Review network policies

**Image pull errors:**
- Ensure all images are loaded: `./scripts/load-images.sh`
- Check image names in values file

### Logs

View application logs:

```bash
# API logs
kubectl logs -n qes-platform -l app.kubernetes.io/name=qes-platform-api

# Database logs
kubectl logs -n qes-platform -l app.kubernetes.io/name=postgresql
```

### Support

For issues specific to your deployment:
1. Check logs and events
2. Review configuration
3. Consult the troubleshooting guide
4. Contact support with logs and configuration

## Uninstalling

To remove QES Platform:

```bash
./scripts/uninstall.sh
```

This will prompt for confirmation before removing components.
EOF

    # Create other docs
    cp "$PROJECT_ROOT/docs/SECURITY.md" "$PACKAGE_DIR/docs/" 2>/dev/null || true
    cp "$PROJECT_ROOT/docs/ARCHITECTURE.md" "$PACKAGE_DIR/docs/" 2>/dev/null || true
    
    echo "✅ Documentation created"
}

# Function to create the final package
create_final_package() {
    echo "📦 Creating final package..."
    
    cd "$INSTALLER_DIR"
    
    # Create checksums
    echo "🔐 Generating checksums..."
    find "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}" -type f -exec sha256sum {} \; > "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}/CHECKSUMS.txt"
    
    # Create tarball
    echo "🗜️  Creating tarball..."
    tar -czf "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz" "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}/"
    
    # Generate final checksum
    sha256sum "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz" > "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz.sha256"
    
    local package_size
    package_size=$(du -h "${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz" | cut -f1)
    
    echo ""
    echo "✅ Package created successfully!"
    echo ""
    echo "📦 Package: ${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz"
    echo "📏 Size: $package_size"
    echo "📁 Location: $INSTALLER_DIR"
    echo ""
    echo "🚀 Installation instructions:"
    echo "1. Transfer the package to your target environment"
    echo "2. Extract: tar -xzf ${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz"
    echo "3. Follow docs/INSTALLATION.md"
}

# Function to show usage
show_usage() {
    cat << EOF
QES Platform Offline Installer Builder

Usage: $0 [OPTIONS]

Options:
    --version VERSION     Set package version (default: 1.0.0)
    --include-samples     Include sample data and configurations
    --minimal             Create minimal package (core components only)
    --help               Show this help message

Examples:
    $0                           # Create standard offline package
    $0 --version 1.2.0          # Create package with specific version
    $0 --minimal                # Create minimal package
    $0 --include-samples        # Include sample data

The offline package includes:
- Container images for all components
- Helm charts and configuration
- Installation and management scripts
- Documentation and troubleshooting guides

Package will be created in: $INSTALLER_DIR
EOF
}

# Parse command line arguments
INCLUDE_SAMPLES=false
MINIMAL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --include-samples)
            INCLUDE_SAMPLES=true
            shift
            ;;
        --minimal)
            MINIMAL=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo "Starting offline installer creation..."
    
    check_prerequisites
    create_package_structure
    export_container_images
    package_helm_charts
    create_config_files
    create_installation_scripts
    create_documentation
    create_final_package
    
    echo ""
    echo "🎉 Offline installer created successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Transfer the package to your air-gapped environment"
    echo "2. Extract and follow the installation guide"
    echo "3. Run the installation scripts"
    echo ""
    echo "Package location: $INSTALLER_DIR/${PACKAGE_NAME}-${VERSION}-${TIMESTAMP}.tar.gz"
}

# Run main function
main "$@"