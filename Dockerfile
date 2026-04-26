FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /trivy-dashboard ./cmd/api

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /trivy-dashboard /trivy-dashboard
COPY migrations/ /migrations/
ENV MIGRATIONS_DIR=/migrations
EXPOSE 8080
ENTRYPOINT ["/trivy-dashboard"]
