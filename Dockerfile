FROM --platform=$BUILDPLATFORM golang:1.23 AS build

ARG BUILDPLATFORM
ARG TARGETARCH
ARG VERSION

COPY . .
RUN GOOS=linux GOARCH=$TARGETARCH go build -o /bin/argocd-proxy .

FROM golang:1.23

COPY --from=build /bin/argocd-proxy /usr/local/bin/argocd-proxy

ENTRYPOINT ["/usr/local/bin/argocd-proxy"]
