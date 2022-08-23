module github.com/oneconcern/keycloak-gatekeeper

replace github.com/coreos/go-oidc => github.com/coreos/go-oidc v0.0.0-20171020180921-e860bd55bfa7

replace github.com/heptiolabs/healthcheck => github.com/heptiolabs/healthcheck v0.0.0-20180807145615-6ff867650f40

// have to deal with some incompatibilities in the jaeger exporter
replace github.com/uber/jaeger-client-go => github.com/uber/jaeger-client-go v2.25.0+incompatible

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	github.com/DataDog/datadog-go v4.8.3+incompatible // indirect
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20220622145613-731d59e8b567
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/PuerkitoBio/purell v1.2.0
	github.com/armon/go-proxyproto v0.0.0-20210323213023-7e956b284f0a
	github.com/boltdb/bolt v1.3.1
	github.com/coreos/go-oidc v0.0.0-00010101000000-000000000000
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/elazarl/goproxy v0.0.0-20220529153421-8ea89ba92021
	github.com/fsnotify/fsnotify v1.5.4
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/csrf v1.7.1
	github.com/gorilla/websocket v1.5.0
	github.com/jonboulle/clockwork v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/prometheus/client_golang v1.13.0
	github.com/rs/cors v1.8.2
	github.com/stretchr/testify v1.8.0
	github.com/tinylib/msgp v1.1.6 // indirect
	github.com/unrolled/secure v1.0.9
	github.com/urfave/cli v1.22.9
	go.opencensus.io v0.23.0
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.22.0
	golang.org/x/crypto v0.0.0-20220817201139-bc19a97f63c8
	golang.org/x/net v0.0.0-20220822230855-b0a4917ee28c
	golang.org/x/sync v0.0.0-20220819030929-7fc1605a5dde // indirect
	golang.org/x/sys v0.0.0-20220818161305-2296e01440c6 // indirect
	golang.org/x/tools v0.1.12 // indirect
	google.golang.org/api v0.94.0 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.39.1 // indirect
	gopkg.in/bsm/ratelimit.v1 v1.0.0-20160220154919-db14e161995a // indirect
	gopkg.in/redis.v4 v4.2.4
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v3 v3.0.1
)

go 1.14
