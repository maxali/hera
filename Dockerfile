## Builder image
FROM golang:1.23-alpine3.20 AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src
COPY . .
RUN go mod tidy
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /dist/hera

## Final image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tini

# Download cloudflared
ADD https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 /bin/cloudflared
RUN chmod +x /bin/cloudflared

COPY --from=builder /dist/hera /bin/

# tini handles PID 1 responsibilities (signal forwarding, zombie reaping)
# Hera runs as PID 2 and just manages cloudflared processes
ENTRYPOINT ["/sbin/tini", "--", "/bin/hera"]
