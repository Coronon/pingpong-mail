# The deployed email server runs as root to avoid frustrations when using
# mounted certbots certificates in the container (no permissions denied errors).

#* Build
FROM golang:latest AS build

WORKDIR /go/src/app

# Resolve app dependencies.
COPY go.mod ./
COPY go.sum ./
RUN set -eux; go mod download; go mod verify

# Copy app source code (except anything in .dockerignore).
COPY . .

# Build app (statically linked).
RUN set -eux; CGO_ENABLED=0 go build -ldflags="-w -s" -o pingpong-mail ./cmd/pingpong-mail

#* Deploy
# Build minimal serving image from compiled `pingpong-mail`.
FROM scratch AS deploy

# Copy basic runtime.
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates

# Copy built binary and config.
COPY --from=build /go/src/app/pingpong-mail /pingpong-mail
COPY --from=build /go/src/app/pingpong.yml /pingpong.yml 

# Run app.
CMD ["/pingpong-mail", "-c", "/pingpong.yml"]
