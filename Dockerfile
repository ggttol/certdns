# Stage 1: Build Go static binary
FROM golang:1.27-alpine AS builder
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/certdns ./cmd/certdns

# Stage 2: Minimal runtime image
FROM alpine:3.22
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Shanghai
COPY --from=builder /out/certdns /usr/local/bin/certdns
VOLUME ["/data"]
EXPOSE 9080
ENTRYPOINT ["/usr/local/bin/certdns"]
