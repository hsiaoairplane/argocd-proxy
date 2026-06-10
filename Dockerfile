FROM --platform=$BUILDPLATFORM golang:1.26 AS build

ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -ldflags="-s -w" -o /bin/argocd-proxy .

FROM gcr.io/distroless/static:nonroot

COPY --from=build /bin/argocd-proxy /usr/local/bin/argocd-proxy

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/argocd-proxy"]
