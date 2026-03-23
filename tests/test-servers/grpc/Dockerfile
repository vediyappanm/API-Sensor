FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 go build -o grpc-server .

FROM alpine:3.19
COPY --from=builder /app/grpc-server /grpc-server
EXPOSE 50051
CMD ["/grpc-server"]
