// Package neonapiratelimiter implements GCRA rate limiting based
// middleware with a Redis data store.
package neonapiratelimiter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/go-redis/redis/v8"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/ip"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/tracing"
	"github.com/vulcand/oxy/v2/utils"
)

const (
	typeName               = "NeonAPIRateLimiterType"
	redisClThrottleCmd     = "CL.THROTTLE"
	redisThrottleKeyPrefix = "traefik:throttle"
	redisAPITokenKeyPrefix = "traefik:token"
)

// Environment variables that can be utilized instead of or
// to override values read from the dynamic, kubernetes CRD configurations.
// These are also in place for utilization within kubernetes,
// where the auto generated CRDs for this middleware exclude
// any sensitive values when serializing to JSON so that they
// are not exposed within the UI dashboard.
var (
	envRedisUsername          = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_USERNAME")
	envRedisPass              = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_PASS")
	envRedisStorageTinkKeyset = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_STORAGE_TINK_KEYSET")
	envRedisTlsCa             = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_TLS_CA")
	envRedisTlsCert           = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_TLS_CERT")
	envRedisTlsKey            = os.Getenv("TRAEFIK_MIDDLEWARES_NEONAPIRATELIMITER_REDIS_TLS_KEY")
)

type neonAPIRateLimiterRedisStorage struct {
	encrypt          bool
	encryptKeyset    *keyset.Handle
	encryptPrimitive tink.DeterministicAEAD
}

type neonAPIRateLimiterRedis struct {
	keyPrefix string
	client    *redis.Client
	storage   *neonAPIRateLimiterRedisStorage
}

// A rate limit definition.
type rateLimit struct {
	burst  int64
	rate   int64
	period int64
	weight int64
}

// neonAPIRateLimiter implements GCRA rate limiting based
// middleware with a Redis data store.
type neonAPIRateLimiter struct {
	name string

	defaultRateLimit rateLimit

	applyTokenRateLimit bool
	tokenRateLimit      rateLimit

	tokenHeader     string
	tokenQueryParam string

	requestMethodsPassthrough map[string]bool

	sourceMatcher utils.SourceExtractor
	whiteLister   *ip.Checker
	strategy      ip.Strategy

	next http.Handler

	scopes *dynamic.NeonAPIRateLimitScopes

	redis *neonAPIRateLimiterRedis

	authService *dynamic.NeonAPIRateLimitAuthService
	httpClient  *http.Client
}

type throttleResult struct {
	limit      bool
	totalLimit int64
	remaining  int64
	retryAfter int64
	reset      int64
}

type apiTokenVerificationResult struct {
	verified bool
	scopes   string
}

type apiTokenResult struct {
	unlimited        bool
	limit            bool
	rateLimit        rateLimit
	throttleRedisKey string
	useSourceKey     bool
}

type rateLimitResponse struct {
	Message string `json:"message"`
}

// Validates the dynamic configuration for the middleware
func validateConfig(config dynamic.NeonAPIRateLimit) bool {
	if config.Redis == nil || config.AuthService == nil {
		return false
	}
	hasRedis := config.Redis.Host != "" &&
		(config.Redis.Password != "" || envRedisPass != "")
	if !hasRedis {
		return false
	}
	hasAuthService := config.AuthService.ServiceUrl != "" &&
		config.AuthService.TokenVerifyEndpoint != ""
	if !hasAuthService {
		return false
	}
	if config.Redis.UseTls {
		if config.Redis.Tls == nil {
			return false
		}
		if config.Redis.Tls.UseMTls {
			invalidDynamicConf := config.Redis.Tls.Cert == "" || config.Redis.Tls.Key == ""
			invalidEnvConf := envRedisTlsCert == "" || envRedisTlsKey == ""
			if invalidDynamicConf && invalidEnvConf {
				return false
			}
		}
	}
	return true
}

// New returns a rate limiter middleware.
func New(
	ctx context.Context,
	next http.Handler,
	config dynamic.NeonAPIRateLimit,
	name string,
) (http.Handler, error) {
	ctxLog := log.With(
		ctx,
		log.Str(log.MiddlewareName, name),
		log.Str(log.MiddlewareType, typeName),
	)
	logger := log.FromContext(ctxLog)
	logger.Debug("Creating middleware")

	validConfig := validateConfig(config)
	if !validConfig {
		return nil, errors.New("failed to validate neonAPIRateLimiter middleware config")
	}

	if config.SourceCriterion == nil ||
		config.SourceCriterion.IPStrategy == nil &&
			config.SourceCriterion.RequestHeaderName == "" && !config.SourceCriterion.RequestHost {
		config.SourceCriterion = &dynamic.SourceCriterion{
			IPStrategy: &dynamic.IPStrategy{},
		}
	}

	sourceMatcher, err := middlewares.GetSourceExtractor(ctxLog, config.SourceCriterion)
	if err != nil {
		return nil, err
	}

	// If defined with an IPStrategy will identify white listed IPs from source range.
	var checker *ip.Checker = nil
	var strategy ip.Strategy = nil
	var whiteListerErr error
	if config.SourceCriterion.IPStrategy != nil && len(config.SourceRange) > 0 {
		checker, whiteListerErr = ip.NewChecker(config.SourceRange)
		if whiteListerErr != nil {
			logger.Errorf("could not initialize IP white lister: %v", whiteListerErr)
		} else {
			strategy, whiteListerErr = config.SourceCriterion.IPStrategy.Get()
			if whiteListerErr != nil {
				logger.Errorf("could not initialize IP white lister strategy: %v", whiteListerErr)
			}
		}
	}

	burst := config.Burst
	if burst <= 0 {
		burst = 1
	}
	rate := config.Rate
	if rate <= 0 {
		rate = 1
	}
	period := config.Period
	if period <= 0 {
		period = 1
	}
	weight := config.Weight
	if weight <= 0 {
		weight = 1
	}

	tokenBurst := config.TokenBurst
	if tokenBurst <= 0 {
		tokenBurst = 1
	}
	tokenRate := config.TokenRate
	if tokenRate <= 0 {
		tokenRate = 1
	}
	tokenPeriod := config.TokenPeriod
	if tokenPeriod <= 0 {
		tokenPeriod = 1
	}
	tokenWeight := config.TokenWeight
	if tokenWeight <= 0 {
		tokenWeight = 1
	}

	requestMethodsPassthrough := make(map[string]bool)
	if len(config.RequestMethodsPassthrough) > 0 {
		for _, method := range config.RequestMethodsPassthrough {
			if _, hasMethod := requestMethodsPassthrough[method]; !hasMethod {
				switch strings.ToUpper(method) {
				case http.MethodConnect:
					fallthrough
				case http.MethodDelete:
					fallthrough
				case http.MethodGet:
					fallthrough
				case http.MethodHead:
					fallthrough
				case http.MethodOptions:
					fallthrough
				case http.MethodPatch:
					fallthrough
				case http.MethodPost:
					fallthrough
				case http.MethodPut:
					fallthrough
				case http.MethodTrace:
					requestMethodsPassthrough[strings.ToUpper(method)] = true
				default:
					logger.Warnf("failed to parse request method passthrough value: [%s]", method)
				}
			}
		}
	}

	redisConfig, err := initRedisConfig(config.Redis, logger)
	if err != nil {
		logger.Errorf("failed to initialize Redis config: [%v]", err)
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DialContext:         dialer.DialContext,
		},
	}

	return &neonAPIRateLimiter{
		name: name,
		defaultRateLimit: rateLimit{
			burst:  burst,
			rate:   rate,
			period: period,
			weight: weight,
		},
		applyTokenRateLimit: config.ApplyTokenRateLimit,
		tokenRateLimit: rateLimit{
			burst:  tokenBurst,
			rate:   tokenRate,
			period: tokenPeriod,
			weight: tokenWeight,
		},
		tokenHeader:               config.TokenHeader,
		tokenQueryParam:           config.TokenQueryParam,
		requestMethodsPassthrough: requestMethodsPassthrough,
		next:                      next,
		sourceMatcher:             sourceMatcher,
		whiteLister:               checker,
		strategy:                  strategy,
		redis:                     redisConfig,
		httpClient:                httpClient,
		scopes:                    config.Scopes,
		authService:               config.AuthService,
	}, nil
}

func initRedisConfig(
	config *dynamic.NeonAPIRateLimitRedis,
	logger log.Logger,
) (*neonAPIRateLimiterRedis, error) {
	tlsConfig, err := initRedisTlsConfig(config, logger)
	if err != nil {
		logger.Errorf("failed to initialize Redis TLS config: [%v]", err)
		return nil, err
	}
	appliedUsername := ""
	if envRedisUsername != "" {
		appliedUsername = envRedisUsername
	} else if config.Username != "" {
		appliedUsername = config.Username
	}
	var appliedPass string
	if envRedisPass != "" {
		appliedPass = envRedisPass
	} else {
		appliedPass = config.Password
	}
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Username:     appliedUsername,
		Password:     appliedPass,
		DB:           config.Database,
		TLSConfig:    tlsConfig,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		MinIdleConns: 5,
	})
	var keyset *keyset.Handle = nil
	var primitive tink.DeterministicAEAD = nil
	var storageErr error
	if config.Storage.Encrypt {
		keyset, storageErr = initRedisStorageConfig(config.Storage, logger)
		if storageErr != nil {
			logger.Errorf("failed to initialize Redis storage config: [%v]", storageErr)
			return nil, storageErr
		}
		primitive, storageErr = daead.New(keyset)
		if storageErr != nil {
			logger.Errorf("failed to initialize Redis storage config: [%v]", storageErr)
			return nil, storageErr
		}
	}
	return &neonAPIRateLimiterRedis{
		keyPrefix: config.KeyPrefix,
		client:    client,
		storage: &neonAPIRateLimiterRedisStorage{
			encrypt:          config.Storage.Encrypt,
			encryptKeyset:    keyset,
			encryptPrimitive: primitive,
		},
	}, nil
}

func initRedisTlsConfig(
	config *dynamic.NeonAPIRateLimitRedis,
	logger log.Logger,
) (*tls.Config, error) {
	if !config.UseTls {
		return nil, nil
	}
	// Initialize the TLS config with optional verify and server name.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.Tls.Verify,
		ServerName:         config.Host,
	}
	var appliedCa string
	if envRedisTlsCa != "" {
		appliedCa = envRedisTlsCa
	} else if config.Tls.Ca != "" {
		appliedCa = config.Tls.Ca
	}
	if appliedCa != "" {
		// Initialize a root CA to verify against when utilizing
		// a self signed certificate during development.
		roots := x509.NewCertPool()
		hasCaFile := false
		if _, err := os.Stat(appliedCa); err == nil {
			hasCaFile = true
		}
		var rootCaFileData []byte
		if hasCaFile {
			rootCaFileData, err := os.ReadFile(appliedCa)
			if err != nil || rootCaFileData == nil {
				logger.Errorf("failed to read CA cert file: [%v]", err)
				return nil, errors.New("failed to initialize Redis CA cert, client")
			}
		} else {
			rootCaFileData = []byte(appliedCa)
		}
		ok := roots.AppendCertsFromPEM(rootCaFileData)
		if !ok {
			logger.Error("failed to parse CA certificate")
			return nil, errors.New("failed to initialize Redis CA cert, client")
		}
		tlsConfig.RootCAs = roots
	}
	if config.Tls.UseMTls {
		var appliedCert string
		var appliedKey string
		if envRedisTlsCert != "" {
			appliedCert = envRedisTlsCert
		} else if config.Tls.Cert != "" {
			appliedCert = config.Tls.Cert
		}
		if envRedisTlsKey != "" {
			appliedKey = envRedisTlsKey
		} else if config.Tls.Key != "" {
			appliedKey = config.Tls.Key
		}
		var certFileData []byte
		var keyFileData []byte
		hasCertFile := false
		hasKeyFile := false
		if _, err := os.Stat(appliedCert); err == nil {
			hasCertFile = true
		}
		if _, err := os.Stat(appliedKey); err == nil {
			hasKeyFile = true
		}
		if hasCertFile {
			certFileData, err := os.ReadFile(appliedCert)
			if err != nil || certFileData == nil {
				logger.Errorf("failed to read cert file: [%v]", err)
				return nil, errors.New("failed to initialize Redis cert, client")
			}
		} else {
			certFileData = []byte(appliedCert)
		}
		if hasKeyFile {
			keyFileData, err := os.ReadFile(appliedKey)
			if err != nil || keyFileData == nil {
				logger.Errorf("failed to read key file: [%v]", err)
				return nil, errors.New("failed to initialize Redis key, client")
			}
		} else {
			keyFileData = []byte(appliedKey)
		}
		// Load the client cert and key.
		cert, err := tls.X509KeyPair(certFileData, keyFileData)
		if err != nil {
			logger.Errorf("Failed to initialize Redis client certs, [%v]", err)
			return nil, errors.New("failed to initialize Redis client certs")
		}
		// Assign the client certificates to the TLS config.
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// Gets the tink keyset handle based on the configured keyset file
// or generates one when not found.
func initRedisStorageConfig(
	config *dynamic.NeonAPIRateLimitRedisStorage,
	logger log.Logger,
) (*keyset.Handle, error) {
	hasKeysetFile := false
	var appliedKeyset string
	if envRedisStorageTinkKeyset != "" {
		appliedKeyset = envRedisStorageTinkKeyset
	} else {
		appliedKeyset = config.Keyset
	}
	if _, err := os.Stat(appliedKeyset); err == nil {
		hasKeysetFile = true
	}
	var reader keyset.Reader
	if hasKeysetFile {
		// Keyset definition references a file, read from it.
		fileReader, err := os.Open(appliedKeyset)
		if err != nil {
			logger.Errorf("failed to open tink keyset file [%v]", err)
			return nil, err
		}
		defer fileReader.Close()
		// Read the clear text keyset file and create handle.
		reader = keyset.NewJSONReader(fileReader)
	} else if appliedKeyset != "" {
		// Keyset definition references the raw data.
		reader = keyset.NewBinaryReader(bytes.NewReader([]byte(appliedKeyset)))
	} else {
		// Create new DeterministicAEAD keyset if not found.
		keysetHandle, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
		if err != nil {
			logger.Errorf("failed to create tink keyset handle [%v]", err)
			return nil, err
		}
		// Write generated binary keyset data.
		buff := new(bytes.Buffer)
		binaryWriter := keyset.NewBinaryWriter(buff)
		insecurecleartextkeyset.Write(keysetHandle, binaryWriter)
		reader = keyset.NewBinaryReader(buff)
	}
	keysetHandle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		logger.Errorf("failed to read tink keyset [%v]", err)
		return nil, err
	}
	return keysetHandle, nil
}

func (rl *neonAPIRateLimiter) GetTracingInformation() (string, ext.SpanKindEnum) {
	return rl.name, tracing.SpanKindNoneEnum
}

func (rl *neonAPIRateLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := middlewares.GetLoggerCtx(r.Context(), rl.name, typeName)
	logger := log.FromContext(ctx)
	// Determine the source IP of the request.
	// Requires that the excludedIPs property of the sourceCriterion configuration
	// be specified so that the extractor will utilize the X-Forwarded-For
	// header to determine the source.
	source, _, err := rl.sourceMatcher.Extract(r)
	if err != nil {
		logger.Errorf("could not extract source of request: %v", err)
		rl.next.ServeHTTP(w, r)
		return
	}
	// Determine and apply white listed IPs.
	var detectedIP string
	sourcePassthrough := false
	if rl.whiteLister != nil && rl.strategy != nil {
		detectedIP = rl.strategy.GetIP(r)
		err := rl.whiteLister.IsAuthorized(detectedIP)
		if err == nil {
			// White listed IP identified, allow passthrough.
			sourcePassthrough = true
		}
	}
	if sourcePassthrough {
		logger.Debugf("Identified white listed IP %s", detectedIP)
		rl.next.ServeHTTP(w, r)
		return
	}
	if len(rl.requestMethodsPassthrough) > 0 {
		// Check for request method passthrough.
		if rl.requestMethodsPassthrough[r.Method] {
			logger.Debugf("Identified request method passthrough request: [%s]", r.Method)
			rl.next.ServeHTTP(w, r)
			return
		}
	}
	// Determine and apply rate limit parameters based on token.
	var tr *throttleResult
	var throttleError error
	apiTokenResult := rl.processToken(ctx, r, logger)
	// No rate limiting applied if unlimited.
	if apiTokenResult.unlimited {
		rl.next.ServeHTTP(w, r)
		return
	}
	hasSource := (len(source) > 0)
	var appliedThrottleKey string
	var appliedRateLimit *rateLimit
	if apiTokenResult.limit {
		appliedRateLimit = &apiTokenResult.rateLimit
		if !apiTokenResult.useSourceKey {
			appliedThrottleKey = apiTokenResult.throttleRedisKey
		} else if !hasSource {
			logger.Warnf("could not determine source of request, bypassing rate limiter")
			sourcePassthrough = true
		} else {
			appliedThrottleKey = fmt.Sprintf(
				"%s:%s:%s",
				redisThrottleKeyPrefix,
				rl.redis.keyPrefix,
				source,
			)
		}
	} else {
		appliedRateLimit = &rl.defaultRateLimit
		if !hasSource {
			logger.Warnf("could not determine source of request, bypassing rate limiter")
			sourcePassthrough = true
		} else {
			appliedThrottleKey = fmt.Sprintf(
				"%s:%s:%s",
				redisThrottleKeyPrefix,
				rl.redis.keyPrefix,
				source,
			)
		}
	}
	// Determine if the source could not be determined.
	if sourcePassthrough {
		logger.Debugf("Bypassed source: %v", source)
		rl.next.ServeHTTP(w, r)
		return
	}
	// Apply limit.
	tr, throttleError = doThrottle(
		ctx,
		rl.redis.client,
		appliedThrottleKey,
		appliedRateLimit.burst,
		appliedRateLimit.rate,
		appliedRateLimit.period,
		appliedRateLimit.weight,
	)
	if throttleError != nil {
		logger.Errorf("could not process throttling command: %v", throttleError)
		rl.next.ServeHTTP(w, r)
		return
	}
	rl.setRateLimitHeaders(ctx, w, r, tr)
	if tr.limit {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		message := rateLimitResponse{
			Message: "API rate limit exceeded",
		}
		if err := json.NewEncoder(w).Encode(message); err != nil {
			log.FromContext(ctx).Errorf("could not serve 429: %v", err)
		}
		return
	}
	rl.next.ServeHTTP(w, r)
}

func (rl *neonAPIRateLimiter) processToken(
	ctx context.Context,
	r *http.Request,
	logger log.Logger,
) *apiTokenResult {
	// Default the result to utilize the default rate limiter for public consumption.
	result := apiTokenResult{
		unlimited:    false,
		limit:        false,
		useSourceKey: false,
	}
	// Check for API token in header or query parameter.
	token := r.Header.Get(rl.tokenHeader)
	if len(token) <= 0 {
		token = r.URL.Query().Get(rl.tokenQueryParam)
	}
	if len(token) <= 0 {
		return &result
	}
	allowTokenStorage := true
	storedToken := token
	if rl.redis.storage.encrypt {
		encToken, err := rl.encryptString(token, rl.redis.keyPrefix)
		if err != nil {
			logger.Warnf("error encrypting parsed token %v", err)
			allowTokenStorage = false
		} else {
			storedToken = encToken
		}
	}
	tokenRedisKey := fmt.Sprintf(
		"%s:%s:%s",
		redisAPITokenKeyPrefix,
		rl.redis.keyPrefix,
		storedToken,
	)
	verifiedToken := false
	decryptScopes := false
	var storedScopes string
	var err error
	if !allowTokenStorage {
		// If we failed to encrypt the token value when
		// set to encrypt, do not store the value and
		// perform verification only.
		tokenVerify := rl.verifyToken(token, logger)
		if !tokenVerify.verified {
			logger.Warn("could not verify parsed token ***")
		} else {
			verifiedToken = true
			storedScopes = tokenVerify.scopes
		}
	} else {
		// Check for cached key in Redis.
		storedScopes, err = rl.redis.client.Get(ctx, tokenRedisKey).Result()
		if err == redis.Nil {
			// When the err result is redis.Nil, key does not exist.
			// Verify the token with the data service.
			tokenVerify := rl.verifyToken(token, logger)
			if !tokenVerify.verified {
				logger.Warn("could not verify parsed token ***")
			} else {
				verifiedToken = true
				storedScopes = tokenVerify.scopes
				rl.storeRedisSilent(ctx, tokenRedisKey, storedScopes, logger)
			}
		} else if err != nil {
			logger.Warnf("error getting token from Redis with err  %v", err)
		} else {
			// Found token stored in Redis, verified.
			verifiedToken = true
			decryptScopes = rl.redis.storage.encrypt
		}
	}
	// If could not verify token or identify scopes, apply public limit.
	if !verifiedToken || storedScopes == "" {
		result.unlimited = false
		result.limit = false
		return &result
	}
	// Determine if token passthrough mode.
	if verifiedToken && !rl.applyTokenRateLimit {
		result.unlimited = true
		return &result
	}
	var resolvedScopes string
	if !decryptScopes {
		resolvedScopes = storedScopes
	} else {
		decScopes, err := rl.decryptString(storedScopes, rl.redis.keyPrefix)
		if err != nil {
			// If we encountered an error with decrypting the stored scopes,
			// we can fallback to re-verifying the token and obtain
			// parsed scopes from the token.
			logger.Warnf("error decrypting stored scopes %v", err)
			tokenVerify := rl.verifyToken(token, logger)
			if !tokenVerify.verified {
				logger.Warn("could not verify parsed token ***")
			} else {
				resolvedScopes = tokenVerify.scopes
				// Attempt to clean up corrupted value.
				delErr := rl.redis.client.Del(ctx, tokenRedisKey).Err()
				if delErr != nil {
					logger.Warnf("error attempting to remove corrupted value [%v]", delErr)
				}
			}
		} else {
			resolvedScopes = decScopes
		}
	}
	// Determine rate limit params based on scopes in token.
	foundLimit := false
	for _, scope := range strings.Split(resolvedScopes, " ") {
		// Operate only on specified scope prefixes.
		isApplicableScope := false
		for _, scopePrefix := range rl.scopes.PrefixFilter {
			if strings.HasPrefix(scope, scopePrefix) {
				isApplicableScope = true
				break
			}
		}
		if !isApplicableScope {
			continue
		}
		switch scope {
		case rl.scopes.ServiceScopeName:
			fallthrough
		case rl.scopes.RateScopeUnlimitedName:
			foundLimit = true
			result.unlimited = true
		case rl.scopes.RateScopeLimitedName:
			foundLimit = true
			result.limit = true
			result.rateLimit = rl.tokenRateLimit
			if !allowTokenStorage {
				// Indicate that the token is valid, has a limit,
				// but could not prepare the token for storage based on
				// configuration, so do not store but instead as a best effort
				// apply the token specific limit to the source (eg, IP).
				result.useSourceKey = true
			} else {
				// Set the throttle key if we are applying a limit
				// and could successfully prepare the token (eg, encrypt).
				result.throttleRedisKey = fmt.Sprintf(
					"%s:%s:%s",
					redisThrottleKeyPrefix,
					rl.redis.keyPrefix,
					storedToken,
				)
			}
		}
		if foundLimit {
			break
		}
	}
	return &result
}

func (rl *neonAPIRateLimiter) encryptString(value string, ad string) (string, error) {
	encValue, err := rl.redis.storage.encryptPrimitive.EncryptDeterministically(
		[]byte(value),
		[]byte(ad),
	)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encValue), nil
}

func (rl *neonAPIRateLimiter) decryptString(value string, ad string) (string, error) {
	decodedValue, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	decValue, err := rl.redis.storage.encryptPrimitive.DecryptDeterministically(
		decodedValue,
		[]byte(rl.redis.keyPrefix),
	)
	if err != nil {
		return "", err
	}
	return string(decValue), nil
}

func (rl *neonAPIRateLimiter) verifyToken(
	token string,
	logger log.Logger,
) *apiTokenVerificationResult {
	result := apiTokenVerificationResult{
		verified: false,
		scopes:   "",
	}
	result.verified = rl.fetchVerifyToken(token, logger)
	if result.verified {
		rawScopes, err := rl.parseTokenScope(token, logger)
		if err != nil {
			return &result
		}
		result.scopes = rawScopes
	}
	return &result
}

func (rl *neonAPIRateLimiter) fetchVerifyToken(token string, logger log.Logger) bool {
	url := fmt.Sprintf("%s%s", rl.authService.ServiceUrl, rl.authService.TokenVerifyEndpoint)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.Errorf("error verifying token %v", err)
		return false
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add(rl.authService.TokenHeader, token)
	resp, err := rl.httpClient.Do(req)
	if err != nil {
		logger.Errorf("error verifying token %v", err)
		return false
	}
	// Drain and close the body to let the Transport reuse the connection.
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		// Allow process to continue in case of response body drain issue.
		logger.Warnf("error draining token verification response body %v", err)
	}
	return resp.StatusCode == http.StatusOK
}

func (rl *neonAPIRateLimiter) parseTokenScope(token string, logger log.Logger) (string, error) {
	var claims map[string]interface{}
	decodedJwt, err := jwt.ParseSigned(token)
	if err != nil {
		logger.Errorf("error decoding token %v", err)
		return "", err
	}
	err = decodedJwt.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		logger.Errorf("error decoding token claims %v", err)
		return "", err
	}
	if scope, ok := claims[rl.scopes.ClaimName]; ok {
		return scope.(string), nil
	}
	return "", nil
}

func (rl *neonAPIRateLimiter) storeRedisSilent(
	ctx context.Context,
	key string,
	value string,
	logger log.Logger,
) {
	shouldStore := true
	appliedValue := value
	if rl.redis.storage.encrypt {
		encScopes, err := rl.encryptString(appliedValue, rl.redis.keyPrefix)
		if err != nil {
			logger.Warnf("error encrypting parsed scopes %v", err)
			shouldStore = false
		} else {
			appliedValue = encScopes
		}
	}
	if shouldStore {
		err := rl.redis.client.Set(ctx, key, appliedValue, time.Hour*24).Err()
		if err != nil {
			logger.Warnf("error persisting parsed token to Redis %v", err)
		}
	}
}

func throttleCmd(
	ctx context.Context,
	rdb *redis.Client,
	key string,
	burst int64,
	rate int64,
	period int64,
	weight int64,
) (*redis.StringSliceCmd, error) {
	cmd := redis.NewStringSliceCmd(ctx, redisClThrottleCmd, key, burst, rate, period, weight)
	if err := rdb.Process(ctx, cmd); err != nil {
		return cmd, err
	}
	return cmd, nil
}

func doThrottle(
	ctx context.Context,
	rdb *redis.Client,
	key string,
	burst int64,
	rate int64,
	period int64,
	weight int64,
) (*throttleResult, error) {
	cmd, err := throttleCmd(ctx, rdb, key, burst, rate, period, weight)
	if err != nil {
		return nil, err
	}
	r, err := cmd.Result()
	if err != nil || len(r) != 5 {
		return nil, err
	}

	tr := throttleResult{}
	if v, err := strconv.Atoi(r[0]); v == 0 && err == nil {
		tr.limit = false
	} else {
		tr.limit = true
	}
	if v, err := strconv.Atoi(r[1]); v >= 0 && err == nil {
		// The CL.THROTTLE command comes back with totalLimit + 1
		tr.totalLimit = int64(v) - 1
		if tr.totalLimit < 0 {
			tr.totalLimit = 0
		}
	}
	if v, err := strconv.Atoi(r[2]); v >= 0 && err == nil {
		tr.remaining = int64(v)
	}
	if v, err := strconv.Atoi(r[3]); v >= 0 && err == nil {
		tr.retryAfter = int64(v)
	}
	if v, err := strconv.Atoi(r[4]); v >= 0 && err == nil {
		tr.reset = int64(v)
	}

	return &tr, nil
}

func (rl *neonAPIRateLimiter) setRateLimitHeaders(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	result *throttleResult,
) {
	if v := result.totalLimit; v >= 0 {
		w.Header().Add("X-RateLimit-Limit", strconv.Itoa(int(v)))
	}
	if v := result.remaining; v >= 0 {
		w.Header().Add("X-RateLimit-Remaining", strconv.Itoa(int(v)))
	}
	if v := result.reset; v > 0 {
		w.Header().Add("X-RateLimit-Reset", strconv.Itoa(int(v)))
	}
	if result.limit {
		if v := result.retryAfter; v >= 0 {
			if v == 0 {
				w.Header().Add("Retry-After", "1")
			} else {
				w.Header().Add("Retry-After", strconv.Itoa(int(v)))
			}
		}
	}
}
