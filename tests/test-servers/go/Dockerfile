FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go build -o go-api .

FROM alpine:3.19
COPY --from=builder /app/go-api /go-api
EXPOSE 8443
CMD ["/go-api"]
