package guangyapan

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	netutil "github.com/OpenListTeam/OpenList/v4/internal/net"
	"github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

const (
	uploadProxyPath     = "/__openlist_upload"
	uploadTargetHeader  = "X-OpenList-Upload-Target"
	uploadHeadersHeader = "X-OpenList-Upload-Headers"
	uploadSignHeader    = "X-OpenList-Upload-Sign"
)

func parseUploadProxyURL(address, token string) (*url.URL, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, nil
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("upload_proxy_url must be an HTTPS Worker root URL without credentials, path or query")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("upload_proxy_token is required when upload_proxy_url is set")
	}
	u.Path = uploadProxyPath
	u.RawPath = ""
	return u, nil
}

func (d *GuangYaPan) newOSSClient(token *uploadTokenData) (*oss.Client, error) {
	proxyURL, err := parseUploadProxyURL(d.UploadProxyURL, d.UploadProxyToken)
	if err != nil {
		return nil, err
	}
	options := []oss.ClientOption{oss.SecurityToken(token.SessionToken)}
	if proxyURL != nil {
		client := netutil.NewHttpClient()
		client.Transport = &uploadProxyTransport{
			base:     client.Transport,
			endpoint: proxyURL,
			signer:   sign.NewHMACSign([]byte(d.UploadProxyToken)),
		}
		// A Worker redirect must not forward OSS credentials to another host.
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		options = append(options, oss.HTTPClient(client))
	}
	return netutil.NewOSSClient(normalizeOSSEndpoint(token.EndPoint, token.BucketName),
		token.AccessKeyID, token.SecretAccessKey, options...)
}

// uploadProxyTransport tunnels already-signed OSS requests without buffering the
// body or changing the URL/headers that OSS uses to verify its own signature.
type uploadProxyTransport struct {
	base     http.RoundTripper
	endpoint *url.URL
	signer   sign.Sign
}

func (t *uploadProxyTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	delegated := false
	defer func() {
		if !delegated && err != nil && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	if req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" ||
		(req.URL.Port() != "" && req.URL.Port() != "443") {
		return nil, errors.New("upload proxy requires an HTTPS OSS endpoint on port 443")
	}
	switch req.Method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
	default:
		return nil, errors.New("upload proxy only supports OSS upload requests")
	}
	if req.ContentLength < 0 {
		return nil, errors.New("upload proxy requires a known OSS request body length")
	}
	headers := req.Header.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	headerJSON, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	encodedHeaders := base64.RawURLEncoding.EncodeToString(headerJSON)
	target := req.URL.String()
	signature := t.signer.Sign(req.Method+"\n"+target+"\n"+encodedHeaders, time.Now().Add(5*time.Minute).Unix())
	proxied := req.Clone(req.Context())
	proxyURL := *t.endpoint
	proxied.URL = &proxyURL
	proxied.Host = ""
	proxied.Header = make(http.Header)
	proxied.Header.Set(uploadTargetHeader, target)
	proxied.Header.Set(uploadHeadersHeader, encodedHeaders)
	proxied.Header.Set(uploadSignHeader, signature)
	delegated = true
	return t.base.RoundTrip(proxied)
}
