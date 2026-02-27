FROM golang:1.22.2-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ext-proc-mode-override main.go

FROM alpine:3.21.0
WORKDIR /app
COPY --from=builder /app/ext-proc-mode-override .

ENTRYPOINT ["./ext-proc-mode-override"]
