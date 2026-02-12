# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/demo-api main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/demo-api /demo-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/demo-api"]

#podman build --platform linux/amd64 -t fra.ocir.io/frsxwtjslf35/demo-api:0.2.0 .
