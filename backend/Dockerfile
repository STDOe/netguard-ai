FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_SYSTEM_CERTS=true \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/srv/netguard/.venv/bin:$PATH"

WORKDIR /srv/netguard
COPY --from=uv /uv /usr/local/bin/uv
COPY --chmod=0644 pyproject.toml uv.lock ./
RUN --mount=type=secret,id=netguard_ca \
    if [ -f /run/secrets/netguard_ca ]; then export SSL_CERT_FILE=/run/secrets/netguard_ca; fi; \
    uv sync --locked --no-dev --no-install-project && \
    mkdir -p /var/lib/netguard && chown 10001:10001 /var/lib/netguard

COPY --chmod=0644 alembic.ini ./
COPY --chmod=u=rwX,go=rX app ./app
COPY --chmod=u=rwX,go=rX config ./config
COPY --chmod=u=rwX,go=rX migrations ./migrations

USER 10001:10001
EXPOSE 8000
CMD ["sh", "-ec", "alembic upgrade head && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --no-access-log --timeout-graceful-shutdown 10"]
