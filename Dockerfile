FROM --platform=$BUILDPLATFORM golang:1.23 AS build

ARG BUILDPLATFORM
ARG TARGETARCH
ARG VERSION

COPY . /src
RUN cd /src && GOOS=linux GOARCH=$TARGETARCH go build -o argocd-proxy -race -v .

FROM golang:1.23

COPY --from=build /bin/argocd-proxy /usr/local/bin/argocd-proxy

ENTRYPOINT ["/usr/local/bin/argocd-proxy"]
