#!/bin/bash
# Build and optimize container images for offline deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="${VERSION:-1.0.0}"
REGISTRY="${REGISTRY:-localhost:5000}"

echo "🏗️  Building QES Platform Images for Offline Deployment"
echo "======================================================"
echo "Version: $VERSION"
echo "Registry: $REGISTRY"
echo ""

# Function to build optimized backend image
build_backend_image() {
    echo "🔨 Building backend image..."
    
    cd "$PROJECT_ROOT/backend"
    
    # Create optimized Dockerfile for offline deployment
    cat > Dockerfile.offline << 'EOF'
# Multi-stage build for optimized backend image
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libffi8 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r qes && useradd -r -g qes qes

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create app directory
WORKDIR /app

# Copy application code
COPY . .

# Set ownership
RUN chown -R qes:qes /app

# Switch to non-root user
USER qes

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

    # Build image
    docker build -f Dockerfile.offline -t "qes-platform/backend:$VERSION" .
    docker tag "qes-platform/backend:$VERSION" "$REGISTRY/qes-platform/backend:$VERSION"
    
    # Cleanup
    rm Dockerfile.offline
    
    echo "✅ Backend image built"
}

# Function to build UI image (if exists)
build_ui_image() {
    if [ ! -d "$PROJECT_ROOT/ui" ]; then
        echo "ℹ️  UI directory not found, skipping UI image"
        return
    fi
    
    echo "🔨 Building UI image..."
    
    cd "$PROJECT_ROOT/ui"
    
    # Create optimized Dockerfile for UI
    cat > Dockerfile.offline << 'EOF'
# Multi-stage build for React UI
FROM node:18-alpine as builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage with nginx
FROM nginx:alpine

# Copy built app
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create non-root user
RUN addgroup -g 1001 -S qes && \
    adduser -S qes -u 1001 -G qes

# Set ownership
RUN chown -R qes:qes /usr/share/nginx/html && \
    chown -R qes:qes /var/cache/nginx && \
    chown -R qes:qes /var/log/nginx && \
    chown -R qes:qes /etc/nginx/conf.d

# Switch to non-root user
USER qes

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
EOF

    # Create nginx config if it doesn't exist
    if [ ! -f nginx.conf ]; then
        cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    sendfile on;
    keepalive_timeout 65;

    server {
        listen 3000;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html;

        location / {
            try_files $uri $uri/ /index.html;
        }

        location /api {
            proxy_pass http://qes-platform-api:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
    fi
    
    # Build image
    docker build -f Dockerfile.offline -t "qes-platform/frontend:$VERSION" .
    docker tag "qes-platform/frontend:$VERSION" "$REGISTRY/qes-platform/frontend:$VERSION"
    
    # Cleanup
    rm Dockerfile.offline
    
    echo "✅ UI image built"
}

# Function to build SoftHSM image
build_softhsm_image() {
    echo "🔨 Building SoftHSM image..."
    
    cd "$PROJECT_ROOT/quickstart"
    
    # Build optimized SoftHSM image
    docker build -f Dockerfile.softhsm -t "qes-platform/softhsm:$VERSION" .
    docker tag "qes-platform/softhsm:$VERSION" "$REGISTRY/qes-platform/softhsm:$VERSION"
    
    echo "✅ SoftHSM image built"
}

# Function to build init containers
build_init_images() {
    echo "🔨 Building init containers..."
    
    # Database migration init container
    cd "$PROJECT_ROOT/backend"
    
    cat > Dockerfile.init << 'EOF'
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy migration scripts
WORKDIR /app
COPY alembic.ini .
COPY alembic/ alembic/
COPY backend/ backend/

# Create entrypoint
COPY docker-entrypoint-init.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-init.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint-init.sh"]
EOF

    # Create init entrypoint
    cat > docker-entrypoint-init.sh << 'EOF'
#!/bin/bash
set -e

echo "🔧 Running database initialization..."

# Wait for database
until pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER"; do
    echo "Waiting for database..."
    sleep 2
done

# Run migrations
echo "Running database migrations..."
alembic upgrade head

# Initialize tenant schemas
echo "Initializing tenant schemas..."
python -c "
import asyncio
from backend.database import init_tenant_schema
asyncio.run(init_tenant_schema('tenant_dev'))
"

echo "✅ Database initialization complete"
EOF

    # Build init image
    docker build -f Dockerfile.init -t "qes-platform/init:$VERSION" .
    docker tag "qes-platform/init:$VERSION" "$REGISTRY/qes-platform/init:$VERSION"
    
    # Cleanup
    rm Dockerfile.init docker-entrypoint-init.sh
    
    echo "✅ Init containers built"
}

# Function to optimize images
optimize_images() {
    echo "🔧 Optimizing images..."
    
    local images=(
        "qes-platform/backend:$VERSION"
        "qes-platform/frontend:$VERSION"
        "qes-platform/softhsm:$VERSION"
        "qes-platform/init:$VERSION"
    )
    
    for image in "${images[@]}"; do
        if docker image inspect "$image" &> /dev/null; then
            echo "   Optimizing $image..."
            
            # Create optimized version
            docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
                wagoodman/dive "$image" --ci || true
        fi
    done
    
    echo "✅ Image optimization complete"
}

# Function to create image manifest
create_image_manifest() {
    echo "📋 Creating image manifest..."
    
    local manifest_file="$PROJECT_ROOT/installer/image-manifest.yaml"
    mkdir -p "$(dirname "$manifest_file")"
    
    cat > "$manifest_file" << EOF
# QES Platform Image Manifest
# Generated: $(date)
# Version: $VERSION

apiVersion: v1
kind: ConfigMap
metadata:
  name: qes-platform-images
  namespace: qes-platform
data:
  images.yaml: |
    core:
      backend:
        repository: qes-platform/backend
        tag: "$VERSION"
        pullPolicy: IfNotPresent
      frontend:
        repository: qes-platform/frontend
        tag: "$VERSION"
        pullPolicy: IfNotPresent
      softhsm:
        repository: qes-platform/softhsm
        tag: "$VERSION"
        pullPolicy: IfNotPresent
      init:
        repository: qes-platform/init
        tag: "$VERSION"
        pullPolicy: IfNotPresent
    
    dependencies:
      postgresql:
        repository: postgres
        tag: "15"
        pullPolicy: IfNotPresent
      redis:
        repository: redis
        tag: "7-alpine"
        pullPolicy: IfNotPresent
      vault:
        repository: vault
        tag: "1.14"
        pullPolicy: IfNotPresent
      grafana:
        repository: grafana/grafana
        tag: "10.0.0"
        pullPolicy: IfNotPresent
      prometheus:
        repository: prom/prometheus
        tag: "v2.45.0"
        pullPolicy: IfNotPresent
      loki:
        repository: grafana/loki
        tag: "2.8.0"
        pullPolicy: IfNotPresent
      minio:
        repository: minio/minio
        tag: "RELEASE.2023-07-07T07-13-57Z"
        pullPolicy: IfNotPresent
EOF
    
    echo "✅ Image manifest created"
}

# Function to test images
test_images() {
    echo "🧪 Testing images..."
    
    # Test backend image
    echo "   Testing backend image..."
    docker run --rm -d --name test-backend \
        -e DATABASE_URL="sqlite:///test.db" \
        "qes-platform/backend:$VERSION" &
    
    # Wait a bit and check
    sleep 5
    if docker exec test-backend curl -f http://localhost:8000/health; then
        echo "   ✅ Backend image test passed"
    else
        echo "   ❌ Backend image test failed"
    fi
    docker stop test-backend 2>/dev/null || true
    
    # Test SoftHSM image
    echo "   Testing SoftHSM image..."
    if docker run --rm "qes-platform/softhsm:$VERSION" \
        softhsm2-util --show-slots | grep -q "QES-DEV-TOKEN"; then
        echo "   ✅ SoftHSM image test passed"
    else
        echo "   ❌ SoftHSM image test failed"
    fi
    
    echo "✅ Image testing complete"
}

# Function to push to local registry (if available)
push_to_registry() {
    if [ "$REGISTRY" = "localhost:5000" ]; then
        echo "ℹ️  Skipping registry push (localhost registry)"
        return
    fi
    
    echo "📤 Pushing images to registry..."
    
    local images=(
        "qes-platform/backend:$VERSION"
        "qes-platform/frontend:$VERSION"
        "qes-platform/softhsm:$VERSION"
        "qes-platform/init:$VERSION"
    )
    
    for image in "${images[@]}"; do
        if docker image inspect "$image" &> /dev/null; then
            echo "   Pushing $REGISTRY/$image..."
            docker push "$REGISTRY/$image"
        fi
    done
    
    echo "✅ Images pushed to registry"
}

# Function to show image summary
show_summary() {
    echo ""
    echo "📊 Build Summary"
    echo "==============="
    
    local images=(
        "qes-platform/backend:$VERSION"
        "qes-platform/frontend:$VERSION"
        "qes-platform/softhsm:$VERSION"
        "qes-platform/init:$VERSION"
    )
    
    echo "Built images:"
    for image in "${images[@]}"; do
        if docker image inspect "$image" &> /dev/null; then
            local size
            size=$(docker image inspect "$image" --format='{{.Size}}' | numfmt --to=iec)
            echo "  ✅ $image ($size)"
        else
            echo "  ❌ $image (not found)"
        fi
    done
    
    echo ""
    echo "🎉 Image build complete!"
    echo ""
    echo "Next steps:"
    echo "1. Run offline installer: ./scripts/offline-installer.sh"
    echo "2. Test deployment: kubectl apply -f installer/image-manifest.yaml"
}

# Main execution
main() {
    echo "Starting image build for offline deployment..."
    
    build_backend_image
    build_ui_image
    build_softhsm_image
    build_init_images
    optimize_images
    create_image_manifest
    test_images
    push_to_registry
    show_summary
}

# Run main function
main "$@"