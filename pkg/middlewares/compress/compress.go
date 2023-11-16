package compress

import (
	"compress/gzip"
	"context"
	"mime"
	"net/http"
	"slices"

	"github.com/klauspost/compress/gzhttp"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
	"github.com/traefik/traefik/v2/pkg/tracing"
)

const (
	typeName = "Compress"
)

// Compress is a middleware that allows to compress the response.
type compress struct {
	next     http.Handler
	name     string
	excludes []string
	minSize  int
	accepts  []string
}

// New creates a new compress middleware.
func New(ctx context.Context, next http.Handler, conf dynamic.Compress, name string) (http.Handler, error) {
	log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName)).Debug("Creating middleware")

	excludes := []string{"application/grpc"}
	accepts := []string{}
	for _, v := range conf.ExcludedContentTypes {
		mediaType, _, err := mime.ParseMediaType(v)
		if err != nil {
			return nil, err
		}

		excludes = append(excludes, mediaType)
	}
	for _, v := range conf.AcceptedContentTypes {
		mediaType, _, err := mime.ParseMediaType(v)
		if err != nil {
			return nil, err
		}

		accepts = append(accepts, mediaType)
	}

	minSize := gzhttp.DefaultMinSize
	if conf.MinResponseBodyBytes > 0 {
		minSize = conf.MinResponseBodyBytes
	}

	return &compress{next: next, name: name, excludes: excludes, minSize: minSize, accepts: accepts}, nil
}

func (c *compress) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		log.FromContext(middlewares.GetLoggerCtx(context.Background(), c.name, typeName)).Debug(err)
	}

	if slices.Contains(c.excludes, mediaType) {
		c.next.ServeHTTP(rw, req)
	} else {
		ctx := middlewares.GetLoggerCtx(req.Context(), c.name, typeName)
		c.gzipHandler(ctx).ServeHTTP(rw, req)
	}
}

func (c *compress) GetTracingInformation() (string, ext.SpanKindEnum) {
	return c.name, tracing.SpanKindNoneEnum
}

// GZIP handler implementation that wraps the request.
//
// The upstream Traefik compress middleware utilizes the
// github.com/klauspost/compress module that enforces a mutual
// exclusion of excluded types and accepted types. They will
// override one another.
// See accepts:
// https://github.com/klauspost/compress/blob/d7343dffdd1afa44068a76ac08b89bd872d19970/gzhttp/gzip.go#L485
// See excludes:
// https://github.com/klauspost/compress/blob/d7343dffdd1afa44068a76ac08b89bd872d19970/gzhttp/gzip.go#L519
//
// In this implementation, the accepted types take precendence over the excluded
// types when defined in the compress middleware configuration.
// In this case, exclude definitions will still be applied based on
// the requested content type.
func (c *compress) gzipHandler(ctx context.Context) http.Handler {
	var wrapper func(http.Handler) http.HandlerFunc
	var err error
	if len(c.accepts) > 0 {
		wrapper, err = gzhttp.NewWrapper(
			gzhttp.ContentTypes(c.accepts),
			gzhttp.CompressionLevel(gzip.DefaultCompression),
			gzhttp.MinSize(c.minSize))
	} else {
		wrapper, err = gzhttp.NewWrapper(
			gzhttp.ExceptContentTypes(c.excludes),
			gzhttp.CompressionLevel(gzip.DefaultCompression),
			gzhttp.MinSize(c.minSize))
	}
	if err != nil {
		log.FromContext(ctx).Error(err)
	}

	return wrapper(c.next)
}
