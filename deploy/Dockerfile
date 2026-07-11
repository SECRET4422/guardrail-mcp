# GuardRail Enterprise MCP — hardened container image
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GUARDRAIL_MODE=http \
    GUARDRAIL_HOST=0.0.0.0 \
    GUARDRAIL_PORT=8787 \
    GUARDRAIL_ENTERPRISE=1

RUN groupadd --gid 10001 guardrail \
    && useradd --uid 10001 --gid guardrail --shell /usr/sbin/nologin --create-home guardrail

WORKDIR /app

COPY requirements.txt pyproject.toml README.md LICENSE ./
COPY guardrail ./guardrail
COPY config ./config

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install -e . \
    && mkdir -p /var/log/guardrail /repos /workspaces \
    && chown -R guardrail:guardrail /app /var/log/guardrail

USER guardrail

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/ready')" || exit 1

CMD ["python", "-m", "guardrail", "serve", "--mode", "http", "--host", "0.0.0.0", "--port", "8787"]
