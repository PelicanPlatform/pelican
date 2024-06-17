module github.com/pelicanplatform/pelican

// Unpublish Go package as we are not intended to allow users us import our packages for now
retract [v1.0.0, v1.0.5]

go 1.21

require (
	github.com/JGLTechnologies/gin-rate-limit v1.5.4
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137
	github.com/ebitengine/purego v0.6.0
	github.com/gin-gonic/gin v1.9.1
	github.com/glebarez/sqlite v1.10.0
	github.com/go-ini/ini v1.67.0
	github.com/go-kit/log v0.2.1
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/gorilla/csrf v1.7.2
	github.com/grafana/regexp v0.0.0-20221122212121-6b5c0a4cb7fd
	github.com/gwatts/gin-adapter v1.0.0
	github.com/hashicorp/go-version v1.6.0
	github.com/jellydator/ttlcache/v3 v3.1.0
	github.com/jsipprell/keyctl v1.0.4-0.20211208153515-36ca02672b6c
	github.com/lestrrat-go/jwx/v2 v2.0.21
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f
	github.com/oklog/run v1.1.0
	github.com/opensaucerer/grab/v3 v3.0.1
	github.com/opensciencegrid/xrootd-monitoring-shoveler v1.3.0
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/pkg/errors v0.9.1
	github.com/pressly/goose/v3 v3.18.0
	github.com/prometheus/client_golang v1.17.0
	github.com/prometheus/common v0.44.0
	github.com/prometheus/prometheus v0.48.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.18.2
	github.com/stretchr/testify v1.9.0
	github.com/studio-b12/gowebdav v0.9.0
	github.com/tg123/go-htpasswd v1.2.1
	github.com/thomas-tacquet/gormv2-logrus v1.2.3
	github.com/vbauerster/mpb/v8 v8.6.1
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a
	github.com/zsais/go-gin-prometheus v0.1.0
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.24.0
	golang.org/x/net v0.26.0
	golang.org/x/oauth2 v0.15.0
	golang.org/x/term v0.21.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.25.7
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.69
)

require (
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/go-stomp/stomp/v3 v3.0.3 // indirect
	github.com/gofrs/flock v0.7.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/sessions v1.2.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/joncrlsn/dque v0.0.0-20211108142734-c2ef48c5192a // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/redis/go-redis/v9 v9.0.2 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sethvargo/go-retry v0.2.4 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/streadway/amqp v1.0.0 // indirect
	go.opentelemetry.io/collector/pdata v1.0.0-rcv0016 // indirect
	go.opentelemetry.io/collector/semconv v0.87.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231120223509-83a465c0220f // indirect
	google.golang.org/grpc v1.59.0 // indirect
	modernc.org/sqlite v1.28.0 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.11.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.6.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.8.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962 // indirect
	github.com/VividCortex/ewma v1.2.0
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go v1.45.25 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/sonic v1.9.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/dennwc/varint v1.0.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/fsnotify/fsnotify v1.7.0
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/gin-contrib/sessions v0.0.5
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.21.4 // indirect
	github.com/go-openapi/errors v0.20.4 // indirect
	github.com/go-openapi/jsonpointer v0.20.0 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/loads v0.21.2 // indirect
	github.com/go-openapi/spec v0.20.9 // indirect
	github.com/go-openapi/strfmt v0.21.7 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/go-openapi/validate v0.22.1 // indirect
	github.com/go-playground/locales v0.14.1
	github.com/go-playground/universal-translator v0.18.1
	github.com/go-playground/validator/v10 v10.16.0
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.6.0
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/oschwald/maxminddb-golang v1.11.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/alertmanager v0.26.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common/assets v0.2.0 // indirect
	github.com/prometheus/common/sigv4 v0.1.0 // indirect
	github.com/prometheus/exporter-toolkit v0.10.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shurcooL/httpfs v0.0.0-20230704072500-f1e31cf0ba5c // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	go.mongodb.org/mongo-driver v1.12.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.45.0 // indirect
	go.opentelemetry.io/otel v1.20.0 // indirect
	go.opentelemetry.io/otel/metric v1.20.0 // indirect
	go.opentelemetry.io/otel/trace v1.20.0 // indirect
	go.uber.org/goleak v1.2.1 // indirect
	golang.org/x/arch v0.3.0 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
	golang.org/x/sync v0.7.0
	golang.org/x/text v0.16.0
	golang.org/x/time v0.5.0
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.69 // indirect
	modernc.org/libc v1.32.0 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.7.2 // indirect
)
