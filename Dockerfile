# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=2.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/honeylambda/ ./cmd/honeylambda/
COPY internal/trap/ ./internal/trap/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false \
    -trimpath -ldflags="-s -w -X main.version=$VERSION" \
    -o /honeylambda ./cmd/honeylambda

FROM scratch
ARG CONFIG_DIR=examples
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /honeylambda /honeylambda
COPY --chown=65532:65532 ${CONFIG_DIR}/ /config/
USER 65532:65532
ENV PORT=8080 HONEY_CONFIG=/config/config.json
EXPOSE 8080
ENTRYPOINT ["/honeylambda"]
CMD ["serve"]
