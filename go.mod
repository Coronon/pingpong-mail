module github.com/coronon/pingpong-mail

go 1.25.0

require (
	blitiri.com.ar/go/spf v1.5.1
	github.com/chrj/smtpd v0.3.1
	github.com/domodwyer/mailyak/v3 v3.6.2
	github.com/emersion/go-msgauth v0.6.8
	github.com/google/uuid v1.6.0
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.55.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/domodwyer/mailyak/v3 => ./vendored/github.com/domodwyer/mailyak/v3

require (
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
)
