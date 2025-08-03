#!/bin/bash
# QES Platform Release Script
# Automates the release process including versioning, tagging, and publishing

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CURRENT_VERSION=""
NEW_VERSION=""
RELEASE_TYPE=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_BUILD=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
QES Platform Release Script

Usage: $0 [OPTIONS] RELEASE_TYPE

RELEASE_TYPE:
    major       Increment major version (1.0.0 -> 2.0.0)
    minor       Increment minor version (1.0.0 -> 1.1.0)
    patch       Increment patch version (1.0.0 -> 1.0.1)
    VERSION     Specific version (e.g., 1.2.3)

Options:
    --dry-run           Show what would be done without making changes
    --skip-tests        Skip running tests before release
    --skip-build        Skip building artifacts
    --help              Show this help message

Examples:
    $0 patch                    # Release 1.0.1
    $0 minor                    # Release 1.1.0
    $0 major                    # Release 2.0.0
    $0 1.2.3                    # Release specific version
    $0 --dry-run patch          # Preview patch release
    $0 --skip-tests 1.2.3       # Release without running tests

Prerequisites:
    - Git repository with no uncommitted changes
    - Docker installed and running
    - Helm 3.x installed
    - kubectl configured (for testing)
    - GitHub CLI (gh) installed and authenticated

The script will:
1. Validate prerequisites and current state
2. Run tests (unless --skip-tests)
3. Update version in all relevant files
4. Build and test artifacts (unless --skip-build)
5. Create git tag and commit
6. Generate release notes
7. Create GitHub release
8. Publish Docker images and Helm charts
EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
    
    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        print_error "Repository has uncommitted changes. Please commit or stash them."
        exit 1
    fi
    
    # Check if we're on main/master branch
    local branch=$(git branch --show-current)
    if [[ "$branch" != "main" && "$branch" != "master" ]]; then
        print_warning "Not on main/master branch. Current branch: $branch"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check required tools
    local tools=("docker" "helm" "kubectl" "gh")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check GitHub CLI authentication
    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI not authenticated. Run 'gh auth login'"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

# Function to get current version
get_current_version() {
    if [ -f "$PROJECT_ROOT/VERSION" ]; then
        CURRENT_VERSION=$(cat "$PROJECT_ROOT/VERSION")
    else
        # Try to get from git tags
        CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0")
    fi
    
    print_status "Current version: $CURRENT_VERSION"
}

# Function to calculate new version
calculate_new_version() {
    local release_type="$1"
    
    case "$release_type" in
        major|minor|patch)
            # Parse current version
            local major minor patch
            IFS='.' read -r major minor patch <<< "$CURRENT_VERSION"
            
            case "$release_type" in
                major)
                    NEW_VERSION="$((major + 1)).0.0"
                    ;;
                minor)
                    NEW_VERSION="$major.$((minor + 1)).0"
                    ;;
                patch)
                    NEW_VERSION="$major.$minor.$((patch + 1))"
                    ;;
            esac
            ;;
        *)
            # Assume it's a specific version
            if [[ "$release_type" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                NEW_VERSION="$release_type"
            else
                print_error "Invalid version format: $release_type"
                print_error "Use major|minor|patch or specific version (e.g., 1.2.3)"
                exit 1
            fi
            ;;
    esac
    
    print_status "New version: $NEW_VERSION"
}

# Function to update version in files
update_version_files() {
    print_status "Updating version in files..."
    
    # Update VERSION file
    echo "$NEW_VERSION" > "$PROJECT_ROOT/VERSION"
    
    # Update package.json files
    find "$PROJECT_ROOT" -name "package.json" -not -path "*/node_modules/*" | while read -r file; do
        print_status "  Updating $file"
        sed -i.bak "s/\"version\": \".*\"/\"version\": \"$NEW_VERSION\"/" "$file"
        rm "${file}.bak"
    done
    
    # Update Helm Chart.yaml
    local chart_file="$PROJECT_ROOT/charts/qes-platform/Chart.yaml"
    if [ -f "$chart_file" ]; then
        print_status "  Updating $chart_file"
        sed -i.bak "s/version: .*/version: $NEW_VERSION/" "$chart_file"
        sed -i.bak "s/appVersion: .*/appVersion: $NEW_VERSION/" "$chart_file"
        rm "${chart_file}.bak"
    fi
    
    # Update Python setup.py
    local setup_files=(
        "$PROJECT_ROOT/sdk/python/setup.py"
        "$PROJECT_ROOT/sdk/python/qes_platform/_version.py"
    )
    
    for file in "${setup_files[@]}"; do
        if [ -f "$file" ]; then
            print_status "  Updating $file"
            sed -i.bak "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" "$file"
            sed -i.bak "s/version=\".*\"/version=\"$NEW_VERSION\"/" "$file"
            rm "${file}.bak" 2>/dev/null || true
        fi
    done
    
    # Update Java pom.xml
    local pom_file="$PROJECT_ROOT/sdk/java/pom.xml"
    if [ -f "$pom_file" ]; then
        print_status "  Updating $pom_file"
        sed -i.bak "s/<version>.*<\/version>/<version>$NEW_VERSION<\/version>/" "$pom_file"
        rm "${pom_file}.bak"
    fi
    
    # Update Go mod files
    find "$PROJECT_ROOT" -name "go.mod" | while read -r file; do
        if grep -q "qes-platform" "$file"; then
            print_status "  Updating $file"
            # Go modules don't have version in go.mod, but we can update comments
            sed -i.bak "s|// v.*|// v$NEW_VERSION|" "$file"
            rm "${file}.bak" 2>/dev/null || true
        fi
    done
    
    # Update Docker image tags in values.yaml
    local values_files=(
        "$PROJECT_ROOT/charts/qes-platform/values.yaml"
        "$PROJECT_ROOT/charts/qes-platform/values-production.yaml"
    )
    
    for file in "${values_files[@]}"; do
        if [ -f "$file" ]; then
            print_status "  Updating $file"
            sed -i.bak "s/tag: \".*\"/tag: \"$NEW_VERSION\"/" "$file"
            rm "${file}.bak"
        fi
    done
    
    print_success "Version files updated"
}

# Function to run tests
run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        print_warning "Skipping tests (--skip-tests specified)"
        return
    fi
    
    print_status "Running tests..."
    
    # Run linting
    print_status "  Running linters..."
    if [ -f "$PROJECT_ROOT/backend/requirements-dev.txt" ]; then
        cd "$PROJECT_ROOT/backend"
        python -m black --check .
        python -m flake8 .
        python -m mypy .
    fi
    
    # Run unit tests
    print_status "  Running unit tests..."
    if [ -f "$PROJECT_ROOT/backend/requirements-test.txt" ]; then
        cd "$PROJECT_ROOT/backend"
        python -m pytest tests/ -v --cov=. --cov-report=html
    fi
    
    # Run security scans
    print_status "  Running security scans..."
    if [ -f "$PROJECT_ROOT/scripts/security-scan.sh" ]; then
        "$PROJECT_ROOT/scripts/security-scan.sh" --quick
    fi
    
    # Test Helm chart
    print_status "  Testing Helm chart..."
    cd "$PROJECT_ROOT"
    helm lint charts/qes-platform
    helm template qes-platform charts/qes-platform --values charts/qes-platform/values.yaml > /tmp/qes-template.yaml
    
    print_success "All tests passed"
}

# Function to build artifacts
build_artifacts() {
    if [ "$SKIP_BUILD" = true ]; then
        print_warning "Skipping build (--skip-build specified)"
        return
    fi
    
    print_status "Building artifacts..."
    
    # Build Docker images
    print_status "  Building Docker images..."
    cd "$PROJECT_ROOT"
    
    # Build backend image
    docker build -t "qes-platform/backend:$NEW_VERSION" backend/
    docker tag "qes-platform/backend:$NEW_VERSION" "qes-platform/backend:latest"
    
    # Build SoftHSM image
    docker build -f quickstart/Dockerfile.softhsm -t "qes-platform/softhsm:$NEW_VERSION" quickstart/
    docker tag "qes-platform/softhsm:$NEW_VERSION" "qes-platform/softhsm:latest"
    
    # Build UI image if exists
    if [ -d "$PROJECT_ROOT/ui" ]; then
        docker build -t "qes-platform/frontend:$NEW_VERSION" ui/
        docker tag "qes-platform/frontend:$NEW_VERSION" "qes-platform/frontend:latest"
    fi
    
    # Package Helm chart
    print_status "  Packaging Helm chart..."
    helm package charts/qes-platform --destination dist/
    
    # Build SDKs
    print_status "  Building SDKs..."
    
    # Python SDK
    if [ -f "$PROJECT_ROOT/sdk/python/setup.py" ]; then
        cd "$PROJECT_ROOT/sdk/python"
        python setup.py sdist bdist_wheel
    fi
    
    # JavaScript SDK
    if [ -f "$PROJECT_ROOT/sdk/javascript/package.json" ]; then
        cd "$PROJECT_ROOT/sdk/javascript"
        npm ci
        npm run build
    fi
    
    # Java SDK
    if [ -f "$PROJECT_ROOT/sdk/java/pom.xml" ]; then
        cd "$PROJECT_ROOT/sdk/java"
        mvn clean package
    fi
    
    # Go SDK
    if [ -f "$PROJECT_ROOT/sdk/go/go.mod" ]; then
        cd "$PROJECT_ROOT/sdk/go"
        go build ./...
        go test ./...
    fi
    
    # Create offline installer
    print_status "  Creating offline installer..."
    cd "$PROJECT_ROOT"
    VERSION="$NEW_VERSION" ./scripts/offline-installer.sh
    
    print_success "Artifacts built successfully"
}

# Function to create git tag and commit
create_git_tag() {
    print_status "Creating git tag..."
    
    # Add updated files
    git add -A
    
    # Commit version bump
    git commit -m "Release v$NEW_VERSION

- Update version to $NEW_VERSION
- Update all package files and configurations
- Prepare for release

[skip ci]"
    
    # Create annotated tag
    git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION

QES Platform version $NEW_VERSION

This release includes:
- Production-ready digital signature platform
- eIDAS-compliant QES provider integrations
- Multi-tenant SaaS architecture
- Comprehensive SDK support
- Enterprise-grade security and monitoring

See CHANGELOG.md for detailed release notes."
    
    print_success "Git tag v$NEW_VERSION created"
}

# Function to generate release notes
generate_release_notes() {
    print_status "Generating release notes..."
    
    local release_notes_file="/tmp/qes-release-notes-$NEW_VERSION.md"
    
    cat > "$release_notes_file" << EOF
# QES Platform v$NEW_VERSION

## 🚀 What's New

$(git log --pretty=format:"- %s" "v$CURRENT_VERSION"..HEAD 2>/dev/null || echo "- Initial release")

## 📦 Downloads

### Docker Images
\`\`\`bash
docker pull qes-platform/backend:$NEW_VERSION
docker pull qes-platform/softhsm:$NEW_VERSION
\`\`\`

### Helm Chart
\`\`\`bash
helm repo add qes-platform https://charts.qes-platform.com
helm install qes-platform qes-platform/qes-platform --version $NEW_VERSION
\`\`\`

### Offline Installer
Download the offline installer package for air-gapped deployments.

## 🔧 Installation

### Quick Start (Docker Compose)
\`\`\`bash
curl -O https://raw.githubusercontent.com/qes-platform/qes-platform/v$NEW_VERSION/quickstart/docker-compose.yml
docker-compose up -d
\`\`\`

### Production Deployment (Kubernetes)
\`\`\`bash
helm install qes-platform qes-platform/qes-platform \\
  --version $NEW_VERSION \\
  --values values-production.yaml \\
  --namespace qes-platform \\
  --create-namespace
\`\`\`

## 📚 Documentation

- [Installation Guide](https://docs.qes-platform.com/installation)
- [API Documentation](https://docs.qes-platform.com/api)
- [SDK Documentation](https://docs.qes-platform.com/sdk)
- [Operations Manual](https://docs.qes-platform.com/operations)

## 🔒 Security

This release has been security tested with:
- OWASP ZAP dynamic analysis
- Snyk dependency scanning
- Trivy container scanning
- Semgrep static analysis

## 🐛 Known Issues

- SoftHSM performance limitations in high-load scenarios
- Some QES providers may have regional restrictions
- PDF visual signatures require specific font licensing

## 💡 Upgrade Notes

$(if [ "$CURRENT_VERSION" != "0.0.0" ]; then
echo "### From v$CURRENT_VERSION"
echo ""
echo "1. Backup your data before upgrading"
echo "2. Update Helm chart: \`helm upgrade qes-platform qes-platform/qes-platform --version $NEW_VERSION\`"
echo "3. Run database migrations if required"
echo ""
echo "See [UPGRADE.md](UPGRADE.md) for detailed upgrade instructions."
else
echo "This is the initial release. No upgrade required."
fi)

## 🙏 Thanks

Thanks to all contributors who made this release possible!
EOF
    
    echo "$release_notes_file"
}

# Function to create GitHub release
create_github_release() {
    print_status "Creating GitHub release..."
    
    local release_notes_file
    release_notes_file=$(generate_release_notes)
    
    # Push changes and tags
    git push origin HEAD
    git push origin "v$NEW_VERSION"
    
    # Create GitHub release
    gh release create "v$NEW_VERSION" \
        --title "QES Platform v$NEW_VERSION" \
        --notes-file "$release_notes_file" \
        --draft=false \
        --prerelease=false \
        dist/*.tgz \
        installer/*.tar.gz
    
    # Cleanup
    rm -f "$release_notes_file"
    
    print_success "GitHub release created"
}

# Function to publish artifacts
publish_artifacts() {
    print_status "Publishing artifacts..."
    
    # Note: This is a placeholder for actual publishing
    # In a real scenario, you would:
    # 1. Push Docker images to registry
    # 2. Publish Helm charts to chart repository
    # 3. Publish SDKs to package managers
    
    print_warning "Artifact publishing is not implemented in this demo"
    print_status "In production, this would:"
    print_status "  - Push Docker images to registry"
    print_status "  - Publish Helm charts to chart repository"
    print_status "  - Publish Python SDK to PyPI"
    print_status "  - Publish JavaScript SDK to npm"
    print_status "  - Publish Java SDK to Maven Central"
    print_status "  - Update Go module proxy"
}

# Function to show release summary
show_release_summary() {
    print_success "🎉 Release v$NEW_VERSION completed successfully!"
    echo ""
    echo "📊 Release Summary:"
    echo "  Previous version: $CURRENT_VERSION"
    echo "  New version:      $NEW_VERSION"
    echo "  Release type:     $RELEASE_TYPE"
    echo ""
    echo "✅ Completed steps:"
    echo "  - Version files updated"
    echo "  - Tests executed (unless skipped)"
    echo "  - Artifacts built (unless skipped)"
    echo "  - Git tag created"
    echo "  - GitHub release published"
    echo ""
    echo "🔗 Links:"
    echo "  - GitHub Release: https://github.com/qes-platform/qes-platform/releases/tag/v$NEW_VERSION"
    echo "  - Docker Images:  https://hub.docker.com/u/qes-platform"
    echo "  - Documentation:  https://docs.qes-platform.com"
    echo ""
    echo "📧 Next steps:"
    echo "  - Announce the release on social media"
    echo "  - Update documentation website"
    echo "  - Notify customers and partners"
    echo "  - Monitor for any issues"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        major|minor|patch)
            RELEASE_TYPE="$1"
            shift
            ;;
        [0-9]*.[0-9]*.[0-9]*)
            RELEASE_TYPE="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate arguments
if [ -z "$RELEASE_TYPE" ]; then
    print_error "Release type is required"
    show_usage
    exit 1
fi

# Main execution
main() {
    echo "🚀 QES Platform Release Script"
    echo "=============================="
    echo ""
    
    check_prerequisites
    get_current_version
    calculate_new_version "$RELEASE_TYPE"
    
    echo ""
    echo "📋 Release Plan:"
    echo "  Current version: $CURRENT_VERSION"
    echo "  New version:     $NEW_VERSION"
    echo "  Release type:    $RELEASE_TYPE"
    echo "  Dry run:         $DRY_RUN"
    echo "  Skip tests:      $SKIP_TESTS"
    echo "  Skip build:      $SKIP_BUILD"
    echo ""
    
    if [ "$DRY_RUN" = true ]; then
        print_warning "DRY RUN MODE - No changes will be made"
        echo ""
        echo "Would execute:"
        echo "  1. Update version files"
        echo "  2. Run tests (unless --skip-tests)"
        echo "  3. Build artifacts (unless --skip-build)"
        echo "  4. Create git tag"
        echo "  5. Create GitHub release"
        echo "  6. Publish artifacts"
        echo ""
        exit 0
    fi
    
    # Confirm release
    read -p "Proceed with release? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Release cancelled"
        exit 0
    fi
    
    echo ""
    print_status "Starting release process..."
    
    update_version_files
    run_tests
    build_artifacts
    create_git_tag
    create_github_release
    publish_artifacts
    show_release_summary
}

# Run main function
main "$@"