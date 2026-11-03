# The mock SOAP service of the end-to-end smoke test (test/e2e). The build context is the
# repository root, so that the program builds with the module's go.mod and go.sum (gokrb5).
# Base images as in the repository Dockerfile.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY test/e2e/mocksoap/ test/e2e/mocksoap/

ARG TARGETOS TARGETARCH
# Only the modules the program imports are downloaded.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags '-s -w' -o /out/mocksoap ./test/e2e/mocksoap

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=build /out/mocksoap /bin/mocksoap

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/bin/mocksoap"]
