# The mock SOAP service of the end-to-end smoke test (test/e2e). The build context is the
# repository root, so that the program builds with the module's go.mod and go.sum (gokrb5).
# Base images as in the repository Dockerfile.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie@sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5 AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY test/e2e/mocksoap/ test/e2e/mocksoap/

ARG TARGETOS TARGETARCH
# Only the modules the program imports are downloaded.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -trimpath -ldflags '-s -w' -o /out/mocksoap ./test/e2e/mocksoap

FROM gcr.io/distroless/static:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087

COPY --from=build /out/mocksoap /bin/mocksoap

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/bin/mocksoap"]
