# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
ARG VERSION=dev
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/kilitd ./cmd/kilitd
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kilitd /kilitd
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/kilitd","-db","/data/kilit.db","-blobs","/data/blobs","-addr",":8080"]
