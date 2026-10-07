package guangyapan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

func TestUploadProxyConfiguration(t *testing.T) {
	for _, tt := range []struct {
		address string
		token   string
		wantErr bool
	}{
		{"", "", false},
		{"https://worker.example.com", "secret", false},
		{"https://worker.example.com/", "secret", false},
		{"http://worker.example.com", "secret", true},
		{"https://worker.example.com/path", "secret", true},
		{"https://worker.example.com?token=secret", "secret", true},
		{"https://worker.example.com#fragment", "secret", true},
		{"https://user:pass@worker.example.com", "secret", true},
		{"https://worker.example.com", "", true},
	} {
		t.Run(tt.address+"/"+tt.token, func(t *testing.T) {
			u, err := parseUploadProxyURL(tt.address, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseUploadProxyURL() error = %v", err)
			}
			if err == nil && u != nil && u.Path != uploadProxyPath {
				t.Fatalf("unexpected upload path %q", u.Path)
			}
		})
	}
}

func TestGuangYaPanOSSUploadsThroughWorker(t *testing.T) {
	previous := conf.Conf
	conf.Conf = conf.DefaultConfig("data")
	t.Cleanup(func() { conf.Conf = previous })
	const secret = "test-upload-secret"
	const bucketName = "example-bucket"
	const objectKey = "folder/file +%.bin"
	payload := bytes.Repeat([]byte("abc"), 400000) // Two parts at the driver's 1 MiB size.
	var operations []string
	var uploaded []byte
	var reject bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != uploadProxyPath || r.URL.RawQuery != "" {
			t.Errorf("unexpected Worker URL %s", r.URL)
		}
		targetText := r.Header.Get(uploadTargetHeader)
		encoded := r.Header.Get(uploadHeadersHeader)
		data := r.Method + "\n" + targetText + "\n" + encoded
		if err := sign.NewHMACSign([]byte(secret)).Verify(data, r.Header.Get(uploadSignHeader)); err != nil {
			t.Errorf("invalid proxy signature: %v", err)
			http.Error(w, "invalid proxy signature", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Oss-Security-Token") != "" {
			t.Error("OSS credentials leaked into proxy request headers")
		}
		target, err := url.Parse(targetText)
		if err != nil {
			t.Error(err)
			return
		}
		if target.Host != bucketName+".oss-cn-example.aliyuncs.com" || target.Path != "/"+objectKey {
			t.Errorf("changed OSS destination: %s", target)
		}
		headerJSON, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Error(err)
			return
		}
		var original http.Header
		if err := json.Unmarshal(headerJSON, &original); err != nil {
			t.Error(err)
			return
		}
		if !strings.HasPrefix(original.Get("Authorization"), "OSS test-access-key:") || original.Get("X-Oss-Security-Token") != "test-session-token" {
			t.Errorf("missing OSS authentication headers: %v", original)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if original.Get("Content-Length") != strconv.Itoa(len(body)) || r.ContentLength != int64(len(body)) {
			t.Errorf("body length changed: original=%s, received=%d, header=%d", original.Get("Content-Length"), len(body), r.ContentLength)
		}
		if reject {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"code":403,"message":"upload rejected"}`)
			return
		}
		query := target.Query()
		if query.Has("uploads") {
			operations = append(operations, "init")
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>example-bucket</Bucket><Key>folder/file +%.bin</Key><UploadId>id+with/slash</UploadId></InitiateMultipartUploadResult>`)
			return
		}
		if query.Has("uploadId") && query.Get("uploadId") != "id+with/slash" {
			t.Errorf("upload ID changed: %s", target.RawQuery)
		}
		switch {
		case r.Method == http.MethodPut && query.Has("partNumber"):
			operations = append(operations, "part"+query.Get("partNumber"))
			uploaded = append(uploaded, body...)
			crc := oss.NewCRC(oss.CrcTable(), 0)
			_, _ = crc.Write(body)
			w.Header().Set("X-Oss-Hash-Crc64ecma", strconv.FormatUint(crc.Sum64(), 10))
			w.Header().Set("ETag", `"part-`+query.Get("partNumber")+`"`)
		case r.Method == http.MethodPost:
			operations = append(operations, "complete")
			if !bytes.Contains(body, []byte("part-1")) || !bytes.Contains(body, []byte("part-2")) {
				t.Errorf("completion lost ETags: %s", body)
			}
			_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Bucket>example-bucket</Bucket><Key>file</Key><ETag>complete</ETag></CompleteMultipartUploadResult>`)
		case r.Method == http.MethodPut && len(body) == 0:
			operations = append(operations, "empty")
			w.Header().Set("ETag", `"empty"`)
		default:
			t.Errorf("unexpected OSS request: %s %s", r.Method, target)
		}
	}))
	defer server.Close()
	d := &GuangYaPan{Addition: Addition{UploadProxyURL: server.URL, UploadProxyToken: secret}}
	token := &uploadTokenData{
		EndPoint: "https://oss-cn-example.aliyuncs.com", BucketName: bucketName,
		AccessKeyID: "test-access-key", SecretAccessKey: "test-access-secret", SessionToken: "test-session-token",
	}
	client, err := d.newOSSClient(token)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.HTTPClient.Transport.(*uploadProxyTransport)
	if !ok {
		t.Fatalf("OSS client bypasses upload proxy: %T", client.HTTPClient.Transport)
	}
	transport.base = server.Client().Transport
	bucket, err := client.Bucket(bucketName)
	if err != nil {
		t.Fatal(err)
	}
	file := &stream.FileStream{Obj: &model.Object{Size: int64(len(payload))}, Reader: bytes.NewReader(payload)}
	var progress float64
	if err := d.multipartUploadToOSS(t.Context(), bucket, objectKey, file, func(value float64) { progress = value }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uploaded, payload) || progress != 100 {
		t.Fatalf("upload incomplete: %d bytes, progress %v", len(uploaded), progress)
	}
	if err := bucket.PutObject(objectKey, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"init", "part1", "part2", "complete", "empty"}; !reflect.DeepEqual(operations, want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
	reject = true
	if err := bucket.PutObject(objectKey, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("proxy error was not propagated: %v", err)
	}
	// Leaving the URL empty selects the regular HTTP client, even with a saved key.
	d.UploadProxyURL = ""
	direct, err := d.newOSSClient(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, proxied := direct.HTTPClient.Transport.(*uploadProxyTransport); proxied {
		t.Fatal("empty upload_proxy_url still enables proxy")
	}
}

type uploadRoundTripFunc func(*http.Request) (*http.Response, error)

func (f uploadRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUploadProxyPreservesRequestAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://bucket.oss.example/file?uploadId=a%2Bb", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "OSS original")
	originalURL, originalHeaders, originalBody := req.URL.String(), req.Header.Clone(), req.Body
	endpoint, _ := parseUploadProxyURL("https://worker.example.com", "secret")
	transport := &uploadProxyTransport{
		endpoint: endpoint,
		signer:   sign.NewHMACSign([]byte("secret")),
		base: uploadRoundTripFunc(func(proxied *http.Request) (*http.Response, error) {
			if proxied.Body != originalBody {
				t.Error("proxy buffered or replaced the body")
			}
			cancel()
			select {
			case <-proxied.Context().Done():
				return nil, proxied.Context().Err()
			case <-time.After(time.Second):
				t.Error("proxy lost cancellation")
				return nil, errors.New("timeout")
			}
		}),
	}
	if _, err := transport.RoundTrip(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if req.URL.String() != originalURL || !reflect.DeepEqual(req.Header, originalHeaders) {
		t.Fatal("proxy modified the original OSS request")
	}
}
