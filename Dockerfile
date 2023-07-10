#* Build
FROM golang:latest AS build

# Create non-root user.
ENV USER=notroot
ENV UID=10001
RUN set -eux; adduser \
    --disabled-password \
    --gecos "" \
    --home "/nil" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

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

# Copy previously created user and group files to avoid running as root.
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# Copy basic runtime.
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates

# Copy built binary and config.
COPY --from=build /go/src/app/pingpong-mail /pingpong-mail
COPY --from=build /go/src/app/pingpong.yml /pingpong.yml 

# Run as unprivileged user.
USER notroot:notroot

# Run app.
CMD ["/pingpong-mail", "-c", "/pingpong.yml"]
