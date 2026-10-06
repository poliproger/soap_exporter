# The builder always runs on the build platform and cross-compiles for the target, so
# multi-arch images build without emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS TARGETARCH
ARG VERSION=dev \
    REVISION=unknown \
    BRANCH=unknown \
    BUILD_USER=docker \
    BUILD_DATE=unknown
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X github.com/prometheus/common/version.Version=${VERSION} \
        -X github.com/prometheus/common/version.Revision=${REVISION} \
        -X github.com/prometheus/common/version.Branch=${BRANCH} \
        -X github.com/prometheus/common/version.BuildUser=${BUILD_USER} \
        -X github.com/prometheus/common/version.BuildDate=${BUILD_DATE}" \
      -o /out/soap_exporter ./cmd/soap_exporter

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=build /out/soap_exporter /bin/soap_exporter

# Numeric, so that runAsNonRoot checks can verify it without /etc/passwd.
USER 65532:65532
EXPOSE 10057
ENTRYPOINT ["/bin/soap_exporter"]
CMD ["--config.file=/etc/soap_exporter/config.yml"]
