FROM golang:1.22.2-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o streaming-backend main.go

FROM alpine:3.21.0
WORKDIR /app
COPY --from=builder /app/streaming-backend .

ENTRYPOINT ["./streaming-backend"]
