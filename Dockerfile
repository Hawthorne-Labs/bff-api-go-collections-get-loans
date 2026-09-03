# syntax=docker/dockerfile:1.7
# Portable, hardened image. Shared Go modules can be fetched either:
#   local: DOCKER_BUILDKIT=1 docker build --ssh default -t <name> .
#   CI:    docker build --secret id=GIT_AUTH_USER,env=GIT_AUTH_USER \
#                       --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN -t <name> .
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS builder
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOPRIVATE=github.com/Hawthorne-Labs/* \
    GOPROXY=https://proxy.golang.org,direct

WORKDIR /src

# git + ssh ONLY in the builder to fetch private modules; pin host key.
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts 2>/dev/null

COPY go.mod go.sum ./
RUN --mount=type=ssh,required=false \
    --mount=type=secret,id=GIT_AUTH_USER,required=false \
    --mount=type=secret,id=GIT_AUTH_TOKEN,required=false \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    auth_user_file=/run/secrets/GIT_AUTH_USER; \
    auth_token_file=/run/secrets/GIT_AUTH_TOKEN; \
    if [ -s "$auth_user_file" ] && [ -s "$auth_token_file" ]; then \
      printf 'machine github.com login %s password %s\n' \
        "$(tr -d '\r\n' < "$auth_user_file")" \
        "$(tr -d '\r\n' < "$auth_token_file")" > "$HOME/.netrc"; \
      chmod 0600 "$HOME/.netrc"; \
    elif [ -z "${SSH_AUTH_SOCK:-}" ]; then \
      echo "private Go modules require either --ssh default or GIT_AUTH_USER/GIT_AUTH_TOKEN secrets" >&2; \
      exit 1; \
    else \
      ssh_check="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -T git@github.com 2>&1 || true)"; \
      if ! printf '%s' "$ssh_check" | grep -q "successfully authenticated"; then \
        echo "private Go modules require a forwarded SSH identity with GitHub access or GIT_AUTH_USER/GIT_AUTH_TOKEN secrets" >&2; \
        printf '%s\n' "$ssh_check" >&2; \
        exit 1; \
      fi; \
      git config --global url."git@github.com:".insteadOf "https://github.com/"; \
    fi; \
    go mod download; \
    rm -f "$HOME/.netrc"; \
    git config --global --unset-all url."git@github.com:".insteadOf || true

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=ssh,required=false \
    --mount=type=secret,id=GIT_AUTH_USER,required=false \
    --mount=type=secret,id=GIT_AUTH_TOKEN,required=false \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    auth_user_file=/run/secrets/GIT_AUTH_USER; \
    auth_token_file=/run/secrets/GIT_AUTH_TOKEN; \
    if [ -s "$auth_user_file" ] && [ -s "$auth_token_file" ]; then \
      printf 'machine github.com login %s password %s\n' \
        "$(tr -d '\r\n' < "$auth_user_file")" \
        "$(tr -d '\r\n' < "$auth_token_file")" > "$HOME/.netrc"; \
      chmod 0600 "$HOME/.netrc"; \
    elif [ -n "${SSH_AUTH_SOCK:-}" ]; then \
      git config --global url."git@github.com:".insteadOf "https://github.com/"; \
    else \
      echo "private Go modules require either --ssh default or GIT_AUTH_USER/GIT_AUTH_TOKEN secrets" >&2; \
      exit 1; \
    fi; \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/bff-api ./cmd/server; \
    rm -f "$HOME/.netrc"; \
    git config --global --unset-all url."git@github.com:".insteadOf || true

# Distroless static: no shell, no package manager, no curl/wget/ping/nslookup,
# runs as nonroot (uid 65532). Ships CA certs; the binary is fully static.
FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/bff-api /usr/local/bin/bff-api

EXPOSE 8080
ENV BIND_ADDRESS=0.0.0.0:8080
# No HEALTHCHECK: distroless has no shell/curl by design. Liveness/readiness are
# handled by the orchestrator (k8s httpGet probe / ECS healthCheck) hitting /health.
ENTRYPOINT ["/usr/local/bin/bff-api"]
