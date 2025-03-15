FROM golang:1.24-bookworm AS base
FROM base AS builder

WORKDIR /build

COPY go.mod ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o dns

FROM scratch AS production

WORKDIR /prod

COPY --from=builder /build/dns ./
COPY --from=builder /build/servers.csv ./
COPY --from=builder /build/static ./static

EXPOSE 8080

CMD ["./dns-checker"]