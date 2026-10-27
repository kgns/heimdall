# syntax=docker/dockerfile:1
# Lambda image of the daily report (heimdall_cloud.report) with Kiro CLI,
# which writes the report in headless mode. Built for linux/arm64 by
# terraform (terraform/report.tf) through scripts/push-image, with cloud/ as
# the context. Kiro CLI is fetched on the build platform and checked against
# the release manifest's SHA-256, so the image builds without emulation.
ARG BASE=public.ecr.aws/lambda/python:3.13-arm64@sha256:02f57ee32abc4b34f77d30b9f00555d37eaa2fd6b8b10c2d3e6b79542255ac06
ARG ALPINE=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

FROM --platform=$BUILDPLATFORM ${ALPINE} AS kiro
ARG KIRO_VERSION=2.34.1
ARG KIRO_SHA256=7fd69696bd92014178efc84fd06c671553d1dddad14d987b96cc542a234e4237
RUN set -eu; \
    wget -q -O /tmp/kiro.tgz "https://prod.download.cli.kiro.dev/stable/${KIRO_VERSION}/kirocli-aarch64-linux-musl.tar.gz"; \
    echo "${KIRO_SHA256}  /tmp/kiro.tgz" | sha256sum -c -; \
    mkdir -p /out; \
    tar -xzf /tmp/kiro.tgz -C /tmp; \
    install -m 0755 /tmp/kirocli/bin/kiro-cli /tmp/kirocli/bin/kiro-cli-chat /out/

FROM ${BASE}
COPY --from=kiro /out/ /opt/kiro/bin/
COPY src/heimdall_cloud ${LAMBDA_TASK_ROOT}/heimdall_cloud
ENV KIRO_BIN=/opt/kiro/bin/kiro-cli
CMD ["heimdall_cloud.report.lambda_handler"]
