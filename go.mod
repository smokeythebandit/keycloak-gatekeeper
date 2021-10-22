module github.com/oneconcern/keycloak-gatekeeper

replace github.com/coreos/go-oidc => github.com/coreos/go-oidc v0.0.0-20171020180921-e860bd55bfa7

replace github.com/heptiolabs/healthcheck => github.com/heptiolabs/healthcheck v0.0.0-20180807145615-6ff867650f40

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.0
	github.com/DataDog/datadog-go v4.8.2+incompatible // indirect
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20210527074920-9baf37265e83
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/PuerkitoBio/purell v1.1.1
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/armon/go-proxyproto v0.0.0-20190211145416-68259f75880e
	github.com/boltdb/bolt v1.3.1
	github.com/coreos/go-oidc v0.0.0-00010101000000-000000000000
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/elazarl/goproxy v0.0.0-20190711103511-473e67f1d7d2
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2 // indirect
	github.com/fsnotify/fsnotify v1.5.1
	github.com/garyburd/redigo v1.6.0 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/csrf v1.7.1
	github.com/gorilla/websocket v1.4.2
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/onsi/ginkgo v1.8.0 // indirect
	github.com/onsi/gomega v1.5.0 // indirect
	github.com/prometheus/client_golang v1.11.0
	github.com/rs/cors v1.8.0
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/uber/jaeger-client-go v2.24.0+incompatible // indirect
	github.com/unrolled/secure v1.0.9
	github.com/urfave/cli v1.22.5
	go.opencensus.io v0.23.0
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/net v0.0.0-20211020060615-d418f374d309
	golang.org/x/sys v0.0.0-20211020174200-9d6173849985 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/api v0.28.0 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.33.0 // indirect
	gopkg.in/bsm/ratelimit.v1 v1.0.0-20160220154919-db14e161995a // indirect
	gopkg.in/redis.v4 v4.2.4
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.4.0
)

go 1.14
