# Build in a stock Go builder container
FROM golang:1.20-alpine as builder

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /app/
COPY go.sum /app/
RUN cd /app && go mod download

ADD . /app
RUN cd /app && go build -o blackbox_exporter

# Pull binary into a second stage deploy alpine container
FROM alpine:latest

COPY --from=builder /app/blackbox_exporter /bin/
COPY blackbox.yml   /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
