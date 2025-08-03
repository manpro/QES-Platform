#!/bin/bash

# QES Platform Security Scanning Script
# Runs comprehensive security scans for local development and CI/CD

set -e

echo "🔒 Starting QES Platform Security Scanning..."

# Configuration
REPORT_DIR="security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKEND_DIR="backend"
COMPOSE_FILE="quickstart/docker-compose.yml"

# Create reports directory
mkdir -p $REPORT_DIR

echo "📁 Created reports directory: $REPORT_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install tools if needed
install_security_tools() {
    echo "🔧 Installing security scanning tools..."
    
    # Install Snyk if not present
    if ! command_exists snyk; then
        echo "Installing Snyk..."
        npm install -g snyk
    fi
    
    # Install Safety for Python dependency scanning
    if ! command_exists safety; then
        echo "Installing Safety..."
        pip install safety
    fi
    
    # Install Bandit for Python security linting
    if ! command_exists bandit; then
        echo "Installing Bandit..."
        pip install bandit
    fi
    
    # Install Semgrep
    if ! command_exists semgrep; then
        echo "Installing Semgrep..."
        pip install semgrep
    fi
    
    echo "✅ Security tools installation complete"
}

# Function to run Python dependency scanning
run_dependency_scan() {
    echo "🔍 Running dependency vulnerability scanning..."
    
    cd $BACKEND_DIR
    
    # Snyk scan
    if command_exists snyk; then
        echo "Running Snyk scan..."
        snyk test --json > ../$REPORT_DIR/snyk-report-$TIMESTAMP.json || true
        snyk test --severity-threshold=high || true
    fi
    
    # Safety scan
    if command_exists safety; then
        echo "Running Safety scan..."
        safety check --json --output ../$REPORT_DIR/safety-report-$TIMESTAMP.json || true
        safety check --short-report || true
    fi
    
    cd ..
    echo "✅ Dependency scanning complete"
}

# Function to run static code analysis
run_static_analysis() {
    echo "🔍 Running static code analysis..."
    
    # Bandit scan for Python security issues
    if command_exists bandit; then
        echo "Running Bandit security scan..."
        bandit -r $BACKEND_DIR -f json -o $REPORT_DIR/bandit-report-$TIMESTAMP.json || true
        bandit -r $BACKEND_DIR -f txt || true
    fi
    
    # Semgrep scan
    if command_exists semgrep; then
        echo "Running Semgrep analysis..."
        semgrep --config=auto --json --output=$REPORT_DIR/semgrep-report-$TIMESTAMP.json $BACKEND_DIR || true
        semgrep --config=p/security-audit --config=p/secrets --config=p/owasp-top-ten $BACKEND_DIR || true
    fi
    
    echo "✅ Static analysis complete"
}

# Function to run container security scanning
run_container_scan() {
    echo "🐳 Running container security scanning..."
    
    # Build container for scanning
    echo "Building container..."
    docker build -t qes-platform/backend:security-scan $BACKEND_DIR
    
    # Trivy container scan
    if command_exists trivy; then
        echo "Running Trivy container scan..."
        trivy image --format json --output $REPORT_DIR/trivy-container-$TIMESTAMP.json qes-platform/backend:security-scan || true
        trivy image --severity HIGH,CRITICAL qes-platform/backend:security-scan || true
    else
        echo "Trivy not installed, running with Docker..."
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v $(pwd)/$REPORT_DIR:/reports \
            aquasec/trivy:latest image --format json --output /reports/trivy-container-$TIMESTAMP.json \
            qes-platform/backend:security-scan || true
    fi
    
    echo "✅ Container scanning complete"
}

# Function to run dynamic application security testing
run_dast_scan() {
    echo "🌐 Running dynamic application security testing..."
    
    # Start the application
    echo "Starting application..."
    docker-compose -f $COMPOSE_FILE up -d
    
    # Wait for application to be ready
    echo "Waiting for application to start..."
    timeout 120 bash -c 'until curl -f http://localhost:8000/health; do sleep 5; done' || {
        echo "❌ Application failed to start within timeout"
        docker-compose -f $COMPOSE_FILE logs
        return 1
    }
    
    # Run OWASP ZAP baseline scan
    echo "Running OWASP ZAP baseline scan..."
    docker run --rm -v $(pwd):/zap/wrk/:rw \
        -t owasp/zap2docker-stable zap-baseline.py \
        -t http://host.docker.internal:8000 \
        -J $REPORT_DIR/zap-baseline-$TIMESTAMP.json \
        -r $REPORT_DIR/zap-baseline-$TIMESTAMP.html || true
    
    # Stop the application
    echo "Stopping application..."
    docker-compose -f $COMPOSE_FILE down -v
    
    echo "✅ Dynamic scanning complete"
}

# Function to run infrastructure security scanning
run_infrastructure_scan() {
    echo "🏗️ Running infrastructure security scanning..."
    
    # Scan Docker Compose files
    if command_exists trivy; then
        echo "Scanning Docker Compose configuration..."
        trivy config --format json --output $REPORT_DIR/trivy-config-$TIMESTAMP.json quickstart/ || true
        trivy config quickstart/ || true
    fi
    
    # Scan Kubernetes configurations if present
    if [ -d "charts" ]; then
        echo "Scanning Helm charts..."
        trivy config --format json --output $REPORT_DIR/trivy-k8s-$TIMESTAMP.json charts/ || true
        trivy config charts/ || true
    fi
    
    echo "✅ Infrastructure scanning complete"
}

# Function to generate consolidated report
generate_report() {
    echo "📊 Generating consolidated security report..."
    
    REPORT_FILE="$REPORT_DIR/security-summary-$TIMESTAMP.md"
    
    cat > $REPORT_FILE << EOF
# QES Platform Security Scan Report

**Date**: $(date)
**Scan ID**: $TIMESTAMP

## Summary

This report contains the results of comprehensive security scanning performed on the QES Platform.

## Scans Performed

### 1. Dependency Vulnerability Scanning
- **Snyk**: Checks for known vulnerabilities in Python dependencies
- **Safety**: Python package security database scan

### 2. Static Code Analysis
- **Bandit**: Python security linting
- **Semgrep**: Multi-language static analysis

### 3. Container Security Scanning
- **Trivy**: Container image vulnerability scanning

### 4. Dynamic Application Security Testing
- **OWASP ZAP**: Web application security testing

### 5. Infrastructure Security Scanning
- **Trivy Config**: Infrastructure as Code security scanning

## Report Files

EOF

    # List all generated report files
    ls -la $REPORT_DIR/*$TIMESTAMP* >> $REPORT_FILE 2>/dev/null || true
    
    cat >> $REPORT_FILE << EOF

## Recommendations

1. Review all HIGH and CRITICAL severity findings
2. Update dependencies with known vulnerabilities
3. Fix any static analysis security issues
4. Address container security findings
5. Remediate any dynamic scan vulnerabilities

## Next Steps

1. Prioritize findings based on CVSS scores and exploitability
2. Create tickets for remediation work
3. Implement additional security controls as needed
4. Schedule regular security scanning

EOF

    echo "✅ Report generated: $REPORT_FILE"
}

# Function to run all scans
run_all_scans() {
    echo "🚀 Running comprehensive security scanning suite..."
    
    install_security_tools
    run_dependency_scan
    run_static_analysis
    run_container_scan
    run_infrastructure_scan
    
    # Only run DAST if specifically requested (can be slow)
    if [ "$1" = "--include-dast" ]; then
        run_dast_scan
    else
        echo "ℹ️  Skipping DAST scan (use --include-dast to include)"
    fi
    
    generate_report
    
    echo "🎉 Security scanning complete!"
    echo "📁 Reports available in: $REPORT_DIR"
}

# Function to show usage
show_usage() {
    cat << EOF
QES Platform Security Scanner

Usage: $0 [OPTIONS]

Options:
    --deps          Run dependency scanning only
    --static        Run static analysis only
    --container     Run container scanning only
    --dast          Run dynamic application security testing only
    --infrastructure Run infrastructure scanning only
    --include-dast  Include DAST in full scan (slower)
    --all           Run all scans (default)
    --help          Show this help message

Examples:
    $0                    # Run all scans except DAST
    $0 --include-dast     # Run all scans including DAST
    $0 --deps             # Run only dependency scanning
    $0 --static           # Run only static analysis

EOF
}

# Main execution
case "${1:---all}" in
    --deps)
        install_security_tools
        run_dependency_scan
        ;;
    --static)
        install_security_tools
        run_static_analysis
        ;;
    --container)
        run_container_scan
        ;;
    --dast)
        run_dast_scan
        ;;
    --infrastructure)
        run_infrastructure_scan
        ;;
    --all)
        run_all_scans
        ;;
    --include-dast)
        run_all_scans --include-dast
        ;;
    --help)
        show_usage
        ;;
    *)
        echo "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac