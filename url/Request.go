package url

import (
	"github.com/CyiceK/chttp-mix"
	"github.com/CyiceK/chttp-mix/cookiejar"
	"github.com/CyiceK/chttp-mix/http2"
	ja3 "github.com/CyiceK/requests_mix/transport"
	"time"
)

func NewRequest() *Request {
	return &Request{
		AllowRedirects: true,
		Verify:         true,
	}
}

type Request struct {
	Params         *Params
	Headers        *http.Header
	Cookies        *cookiejar.Jar
	Data           *Values
	Files          *Files
	Json           map[string]interface{}
	Body           string
	Auth           []string
	Timeout        time.Duration
	AllowRedirects bool
	Proxies        string
	Verify         bool
	Cert           []string
	Ja3            string
	ForceHTTP1     bool
	TLSExtensions  *ja3.TLSExtensions
	HTTP2Settings  *http2.HTTP2Settings
}
