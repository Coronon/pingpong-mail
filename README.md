# PingPong-Mail

PingPong-Mail is a powerful email testing tool that automatically responds to
emails sent to it. Whether you need to test the sending and receiving
capabilities of your email domain or perform uptime monitoring, PingPong-Mail
has got you covered. With comprehensive support for DMARC (SPF and DKIM)
validation, including alignment checks, you don't become a spam relay.

## Table of Contents

- [PingPong-Mail](#pingpong-mail)
  - [Table of Contents](#table-of-contents)
  - [Public instance](#public-instance)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Docker 🐳](#docker-)
    - [Binary](#binary)
  - [Configuration](#configuration)
  - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)

## Public instance

If you simply want to try out PingPong-Mail without hosting it yourself, you can
send emails to:

```txt
check@ping-pong.email
```

There are no content restrictions to your messages other than passing DMARC
verification and being smaller than 1 MiB in size. Other than firewall logs, the
server only logs the recipient addresses of successfully outgoing messages to
prevent inadvertently becoming a spam host. No message contents are stored.

**DISCLAIMER: I am not responsible for any response subjects as they are directly
controlled by incoming messages.**


## Introduction

PingPong-Mail is a powerful email testing service that simplifies the testing of
email services by automatically responding to incoming emails. By configuring
PingPong-Mail as your email server, you can easily check if emails can be sent
and received from your domain by waiting for the automatic reply.
With integrated DMARC support, PingPong-Mail ensures that the service is not
abused as a spam relay and enables testing of correct SPF and DKIM
configurations.

PingPong-Mail was built specifically for usage with Uptime-Robot.
Uptime-Robot seamlessly integrates with PingPong-Mail, allowing for periodic
email send/receive uptime monitoring. Together, they provide a comprehensive
solution for monitoring and testing email functionality.

## Installation

### Docker 🐳

```bash
docker run -d --restart=always -p localhost:25:25 --name pingpong-mail coronon/pingpong-mail:latest
```

### Binary

To use PingPong-Mail, follow these steps:

1. Download the PingPong-Mail source code.

2. Build the project using the following command (optimized, stripped and statically linked):

```bash
CGO_ENABLED=0 go build -ldflags="-w -s" -o pingpong-mail ./cmd/pingpong-mail
```

3. Place the executable in a directory of your choice along with the sample
   configuration file `pingpong.yml` (see below).

## Configuration

Before you can start using PingPong-Mail, you need to configure it properly.
PingPong-Mail tries to locate its configuration in the current working directory
when ran.
Follow these steps to set up the configuration:

1. Open the `pingpong.yml` file in the PingPong-Mail directory.
2. Customize the configuration options according to your requirements. 

```yaml
# Interface# Interface to listen on
# Use 0.0.0.0 to receive connections from all interfaces
bind_host: 0.0.0.0

# Port to listen on
# Most email traffic between servers flows through port 25. Port 587 is mainly
# used for submission from client -> server and should require authentication.
bind_port: 25

# Path to look for a TLS certificate (preferably fullchain)
# The server will periodically reload the certificate to avoid any downtime
# when certificates expire or change. Without a valid TLS configuration, the
# SMTP server will not be able to encrypt traffic.
# Absolute paths with symlinks are recommended.
# You could setup certbot with letsencrypt (and possibly mount in a container):
# /etc/letsencrypt/live/ping-pong.email/fullchain.pem
tls_cert_path:

# Path to look for the corresponding TLS key
# For explanation see above.
tls_key_path:

# Seconds to cache a loaded TLS certificate for
# Reloading the certificates periodically allows changing them without having to
# restart the server itself, thus preventing downtime.
# After the cache duration expires, the certificate is reloaded from the paths
# above. Set to `0` to reload certificates with every request and `-1` to cache
# them indefinitely.
tls_cache_duration: 300

# Minutes before TLS certificate expiry, the cache should be disabled
# This is useful to always look for a new certificate when the current one is
# about to expire. Optimally, this threshold should never be hit and only serve as
# a safety precaution. The default is 48 hours.
tls_cache_expiry_threshold: 1440

# Welcome message for SMTP session upon connection from remote
# Some providers expect the host name of the email server here
smtp_welcome_message: PingPong email tester

# Canonical hostname for this server used when connecting to a remote MTA in the
# HELO/EHLO command to identify ourselves
server_name: mail.ping-pong.email

# Ports to try to deliver replies to in order
# Should probably be left with the default
delivery_ports: [25, 2525, 587]

# Restricts addresses that can be used as the `RCPT TO:` (RFC5321)
# The below value will be treated as a regular expression, so be sure to escape
# any characters with a special meaning, e.g. '.' -> '\.'.
# When using wildcards to allow any recipient domain, beware that some services
# might consider you an open relay for that. Also ensure that you specify
# `reply_address` to not accidentally impersonate anyone!
# If left empty, no checks will be applied and all mail accepted.
restrict_inbox: ^.+@ping-pong\.email$

# Force some string at the beginning of received mails subjects
# Useful when you don't want to service automatic spam emails.
# All emails without this prefix will be rejected. Leave empty to disable.
force_subject_prefix: "PING "

# Maximum size of an email, after which a message is rejected in bytes.
# The default is 1 MiB.
max_message_size: 1048576

# Forces all incoming mail to pass DMARC -> either SPF or DKIM
# You should definitely leave this enabled when your instance is exposed to the
# internet to not become a spam origin. People and bots could fake the sender
# and use the instance effectively as an open relay.
enable_dmarc: true

# Address used in the `MAIL FROM:` (RFC5321) when replying to emails
# You probably want to use one from your domain, but can specify anything.
# Leave this empty to use the first address from `RCPT TO:` (RFC5321) of the
# email responding to.
reply_address: check@ping-pong.email

# Address used in the <From:> header when replying to emails
# RFC 5322 address, e.g. "Barry Gibbs <bg@example.com>"
reply_from: PingPong Email <check@ping-pong.email>

# Subject used when replying to emails
# The variable `{ORIG_SUBJ}` will be replaced with the unaltered subject of the
# received email
reply_subject: PONG - '{ORIG_SUBJ}'

# Message body used when replying to emails
# The variable `{ORIG_BODY}` will be replaced with the unaltered body
# (without headers) of the received email
# The variable `{TIME}` will be replaced with the current ISO 8601 timestamp
# You may not want to include the original message as many email clients add
# content in multiple formats, all ASCII encoded. It should however be fine for
# automatically generated, plain emails.
reply_message: |
  Thank you for using ping-pong.email

  Time: {TIME}
```

3. Save the configuration file to disk.
4. Start PingPong-Mail from within the directory or provide the path to a
configuration file using the `-c` command line argument.

## Usage

Once you have installed and configured PingPong-Mail, you can use it from the
terminal by following these steps:

1. Open a terminal or command prompt.
2. Navigate to the directory where you placed the PingPong-Mail executable.
3. Run the PingPong-Mail executable:

```bash
./pingpong-email
```

4. PingPong-Mail will start listening for incoming emails and auto reply to them
if they meet the requirements.

## Contributing

Contributions to PingPong-Mail are welcome! If you encounter any issues or have
suggestions for improvements, please open an issue on the
[GitHub repository](https://github.com/Coronon/pingpong-email/issues).

If you want to contribute to the project, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make the necessary changes and commit them.
4. Push your branch to your forked repository.
6. Open a pull request on the main repository and provide a detailed description
of your changes.

## License

PingPong-Mail is open-source software licensed under the
[3-Clause BSD License](https://opensource.org/license/bsd-3-clause/).
See the [LICENSE](https://github.com/Coronon/pingpong-email/blob/master/LICENSE)
file for more details.
