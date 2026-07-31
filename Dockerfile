# Backend image for the AIBOM Inspector API + web UI.
# Prefer the launcher (./aibom ui) — it builds and runs this image for you.
# Build:  docker build -t aibom-inspector .
# Run:    docker run -p 8000:8000 aibom-inspector
# The container needs git (for shallow-cloning target repos). It never executes
# the cloned code — the scanner is static.
FROM python:3.12-slim

# git is required by the clone step; nothing else at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the package with the server extra first (better layer caching).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY web ./web
# The demo app ships inside the wheel (aibom/demo_app) for `aibom scan --demo`.
COPY tests/fixtures/vulnerable-ai-app ./tests/fixtures/vulnerable-ai-app
COPY tests/fixtures/impact-demo ./tests/fixtures/impact-demo
COPY tests/fixtures/impact-demo-baseline ./tests/fixtures/impact-demo-baseline
COPY tests/fixtures/impact-demo-ts ./tests/fixtures/impact-demo-ts
COPY tests/fixtures/impact-demo-ts-baseline ./tests/fixtures/impact-demo-ts-baseline
COPY examples/trust-boundary-drift ./examples/trust-boundary-drift
RUN pip install --no-cache-dir ".[server]"

# Run as a non-root user. /out is the writable artifact drop for bind mounts,
# so a read-only source mount at /work never blocks report writing.
RUN useradd --create-home --uid 10001 aibom \
    && mkdir -p /out /work \
    && chown aibom:aibom /out /work
USER aibom
ENV AIBOM_OUTPUT_DIR="/out"

ENV AIBOM_CORS_ORIGINS="*"
# So `aibom serve` (e.g. from the interactive menu) binds reachably in Docker.
ENV AIBOM_HOST="0.0.0.0"
# Serve the bundled UI at / (the package install doesn't keep web/ beside the code).
ENV AIBOM_WEB_DIR="/app/web"
EXPOSE 8000

# Honor $PORT so free hosts that inject it work unchanged (Render, Cloud Run);
# defaults to 8000 locally. Bind to all interfaces inside the container.
CMD ["sh", "-c", "uvicorn aibom.server.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
