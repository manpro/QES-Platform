# QES Platform CLI (qesctl) Docker Image

# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN make build

# Runtime stage
FROM alpine:3.18

# Install required packages
RUN apk add --no-cache \
    ca-certificates \
    git \
    curl \
    bash \
    vim \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -s /bin/bash qes

# Copy binary from builder
COPY --from=builder /app/qesctl /usr/local/bin/qesctl

# Make binary executable
RUN chmod +x /usr/local/bin/qesctl

# Create config directory
RUN mkdir -p /home/qes/.qesctl && chown -R qes:qes /home/qes/.qesctl

# Switch to non-root user
USER qes
WORKDIR /home/qes

# Set environment variables
ENV PATH="/usr/local/bin:${PATH}"
ENV EDITOR=vim

# Create default shell configuration
RUN echo 'alias ll="ls -la"' >> ~/.bashrc && \
    echo 'alias qes="qesctl"' >> ~/.bashrc && \
    echo 'export PS1="\u@qesctl:\w$ "' >> ~/.bashrc

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD qesctl --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["qesctl"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="qesctl"
LABEL org.opencontainers.image.description="QES Platform Configuration CLI"
LABEL org.opencontainers.image.vendor="QES Platform"
LABEL org.opencontainers.image.source="https://github.com/qes-platform/qes-platform"
LABEL org.opencontainers.image.documentation="https://docs.qes-platform.com/tools/qesctl"