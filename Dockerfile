FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION:-dev}" -o /kubescape-exporter ./cmd/kubescape-exporter

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /kubescape-exporter /kubescape-exporter
USER 65534:65534
ENTRYPOINT ["/kubescape-exporter"]
