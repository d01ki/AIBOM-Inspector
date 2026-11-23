# Backend image for the AIBOM Inspector API + web UI (local Docker and Cloud Run).
# Prefer the launcher (./aibom ui): it builds and runs this image for you.
# Build:  docker build -t aibom-inspector .
# Run:    docker run -p 8000:8000 aibom-inspector
# The container needs git (for shallow-cloning target repos). It never executes
# the cloned code: the scanner is static.

# -- build: the wheel, which carries the web UI and the offline demo projects --
FROM python:3.12-slim AS wheel
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY web ./web
# Bundled into the wheel by pyproject's force-include (demo and drift scenarios).
COPY tests/fixtures/vulnerable-ai-app ./tests/fixtures/vulnerable-ai-app
COPY tests/fixtures/impact-demo ./tests/fixtures/impact-demo
COPY tests/fixtures/impact-demo-baseline ./tests/fixtures/impact-demo-baseline
COPY tests/fixtures/impact-demo-ts ./tests/fixtures/impact-demo-ts
COPY tests/fixtures/impact-demo-ts-baseline ./tests/fixtures/impact-demo-ts-baseline
COPY tests/fixtures/xfile-py-baseline ./tests/fixtures/xfile-py-baseline
COPY tests/fixtures/xfile-py-candidate ./tests/fixtures/xfile-py-candidate
COPY tests/fixtures/xfile-ts-baseline ./tests/fixtures/xfile-ts-baseline
COPY tests/fixtures/xfile-ts-candidate ./tests/fixtures/xfile-ts-candidate
COPY examples/trust-boundary-drift ./examples/trust-boundary-drift
COPY examples/agent-privilege-drift ./examples/agent-privilege-drift
COPY examples/mcp-tool-exposure ./examples/mcp-tool-exposure
RUN pip wheel --no-deps --wheel-dir /dist .

# -- runtime --------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# git is required by the clone step; nothing else at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, read from pyproject.toml (the one list), so a code-only
# change reuses this layer instead of reinstalling FastAPI and friends.
COPY pyproject.toml /tmp/pyproject.toml
RUN python -c "import tomllib; p = tomllib.load(open('/tmp/pyproject.toml', 'rb'))['project']; print('\n'.join(p['dependencies'] + p['optional-dependencies']['server']))" > /tmp/requirements.txt \
    && pip install -r /tmp/requirements.txt \
    && rm /tmp/pyproject.toml /tmp/requirements.txt

COPY --from=wheel /dist /tmp/dist
RUN pip install --no-deps /tmp/dist/*.whl && rm -rf /tmp/dist

# Run as a non-root user. /out is the writable artifact drop for bind mounts,
# so a read-only source mount at /work never blocks report writing.
RUN useradd --create-home --uid 10001 aibom \
    && mkdir -p /out /work \
    && chown aibom:aibom /out /work
USER aibom
WORKDIR /work
ENV AIBOM_OUTPUT_DIR="/out"

# No AIBOM_CORS_ORIGINS: the UI is served from the same origin it calls, so
# cross-origin access stays off unless an operator opts in.
# So `aibom serve` (e.g. from the interactive menu) binds reachably in Docker.
ENV AIBOM_HOST="0.0.0.0"
EXPOSE 8000

# `docker run` and Compose see an unhealthy server; Cloud Run ignores this and
# uses its own startup probe on $PORT.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT', '8000'), timeout=4)"

# Honor $PORT so hosts that inject it work unchanged (Cloud Run); defaults to
# 8000 locally. `exec` makes uvicorn PID 1, so the SIGTERM Cloud Run and
# `docker stop` send reaches it and it shuts down gracefully.
CMD ["sh", "-c", "exec uvicorn aibom.server.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
