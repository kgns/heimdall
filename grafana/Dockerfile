# syntax=docker/dockerfile:1
# Grafana with the Athena data source, provisioning and dashboards built in.
# Built for linux/arm64 by terraform (terraform/grafana.tf) through
# scripts/push-image. The plugin is fetched on the build platform so the
# image builds on amd64 without emulation.
ARG GRAFANA_IMAGE=grafana/grafana:13.2.4@sha256:dbbc38ea21103cefb50396340cd88afec779c7e070b0a7bf5a75b4ce46651d3f

FROM --platform=$BUILDPLATFORM ${GRAFANA_IMAGE} AS plugins
ARG TARGETARCH
ARG ATHENA_VERSION=3.4.0
ARG ATHENA_SHA256_ARM64=4317a31c21477a3f396cb30508751ced5d4a737b36d14f393f54a2d700bca6dc
ARG ATHENA_SHA256_AMD64=9040176d74564b6847e3f3652460653862d48acc314d04273826a987d7499ff0
USER root
RUN set -eu; \
    case "$TARGETARCH" in \
      arm64) sum="$ATHENA_SHA256_ARM64" ;; \
      amd64) sum="$ATHENA_SHA256_AMD64" ;; \
      *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/athena.zip \
      "https://grafana.com/api/plugins/grafana-athena-datasource/versions/${ATHENA_VERSION}/download?os=linux&arch=${TARGETARCH}"; \
    echo "$sum  /tmp/athena.zip" | sha256sum -c -; \
    mkdir -p /plugins; \
    unzip -q /tmp/athena.zip -d /plugins; \
    test -f /plugins/grafana-athena-datasource/plugin.json

FROM ${GRAFANA_IMAGE}
COPY --from=plugins --chown=472:0 /plugins/ /var/lib/grafana/plugins/
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/ /etc/grafana/dashboards/
COPY --chmod=0755 entrypoint.sh /heimdall-entrypoint.sh
ENTRYPOINT ["/heimdall-entrypoint.sh"]
