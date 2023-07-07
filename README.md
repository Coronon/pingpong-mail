# PingPong-Mail

PingPong-Mail is a powerful email testing tool that automatically responds to
emails sent to it. Whether you need to test the sending and receiving
capabilities of your email domain or perform uptime monitoring, PingPong-Mail
has got you covered. With comprehensive support for DMARC (SPF and DKIM)
validation, including alignment checks, you don't become a spam relay.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

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

To use PingPong-Mail, follow these steps:

1. Download the PingPong-Mail executable for your operating system from the
[releases](https://github.com/Coronon/pingpong-email/releases) page.

2. Place the executable in a directory of your choice.

## Configuration

Before you can start using PingPong-Mail, you need to configure it properly.
PingPong-Mail tries to locate its configuration in the current working directory
when ran.
Follow these steps to set up the configuration:

1. Open the `pingpong.yml` file in the PingPong-Mail directory.
2. Customize the configuration options according to your requirements. 

```yaml
# Interface to listen on
# Use 0.0.0.0 to receive connections from all interfaces
bind_host: localhost

# Port to listen on
# Most email submission traffic flows through port 587. Port 25 is mainly used
# for relaying these days.
bind_port: 587

# Welcome message for SMTP session upon connection from remote
# Some providers expect the host name of the email server here
smtp_welcome_message: PingPong email tester

# Canonical hostname for this server used when connecting to a remote MTA in the
# HELO/EHLO command to identify ourselves
server_name: mail.ping-pong.email

# Ports to try to deliver replies to in order
# Should probably be left with the default
delivery_ports: [587, 2525, 25]

# Restricts addresses that can be used as the `RCPT TO:` (RFC5321)
# When using the wildcard `*` to allow any recipient address, beware that some
# services might consider you an open relay for that. Also ensure that you
# specify `reply_address` to not accidentally impersonate anyone!
restrict_inbox: check@ping-pong.email

# Force some string at the beginning of received mails subjects
# Useful when you don't want to service automatic spam emails.
# All emails without this prefix will be rejected. Leave empty to disable.
force_subject_prefix: "PING "

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
