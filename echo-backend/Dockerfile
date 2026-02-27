FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go mod init echo-backend && go build -o echo-backend .

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /app/echo-backend .
EXPOSE 8688
ENTRYPOINT ["./echo-backend"]
