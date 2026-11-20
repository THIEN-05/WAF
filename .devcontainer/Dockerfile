FROM mcr.microsoft.com/devcontainers/go:1.24-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG GOLANGCI_LINT_VERSION=v2.0.2
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b /usr/local/bin "${GOLANGCI_LINT_VERSION}"

ENV CGO_ENABLED=1
