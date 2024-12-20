package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	http "github.com/CyiceK/chttp-mix"
	http2 "github.com/CyiceK/chttp-mix/http2"
	gache "github.com/bluele/gcache"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.RWMutex
	// fix typing
	JA3       string
	UserAgent string
	Timeout   int // 无time.Second

	cachedConnections gache.Cache
	//cachedConnections sync.Map
	cachedTransports sync.Map

	dialer        proxy.ContextDialer
	config        *utls.Config
	tlsExtensions *TLSExtensions
	http2Settings *http2.HTTP2Settings
	forceHTTP1    bool
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("user-agent") == "" {
		req.Header.Set("user-agent", rt.UserAgent)
	}
	addr := rt.getDialTLSAddr(req)
	transport, err := rt.getTransport(req, addr)
	if err != nil {
		return nil, err
	}
	return transport.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) (http.RoundTripper, error) {
	transport, okErr := rt.cachedTransports.Load(addr)
	if okErr {
		return transport.(http.RoundTripper), nil
	}

	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		ts := &http.Transport{
			DialContext:       rt.dialer.DialContext,
			DisableKeepAlives: true,
			IdleConnTimeout:   time.Duration(rt.Timeout) * time.Second,
		}
		rt.cachedTransports.Store(addr, ts)
		return ts, nil
	case "https":
	default:
		return nil, fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// TODO: 此处有连接泄漏的问题
	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(rt.Timeout)*time.Second)
	//defer cancel()
	_, err := rt.dialTLS(ctx, cancel, "tcp", addr)

	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		//panic("dialTLS returned no error when determining cachedTransports")
		return nil, fmt.Errorf("dialTLS returned no error when determining cachedTransports")
	default:
		return nil, err
	}
	transport, _ = rt.cachedTransports.Load(addr)

	return transport.(http.RoundTripper), nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, cancel context.CancelFunc, network, addr string) (net.Conn, error) {
	//rt.Lock()
	//defer rt.Unlock()
	defer cancel()
	defer ctx.Done()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	conn, okErr := rt.cachedConnections.Get(addr)
	if okErr == nil {
		return conn.(net.Conn), nil
		//} else {
		//	//rt.Lock()
		//	//defer rt.Unlock()
		//	conn, okErr = rt.cachedConnections.Get(addr)
		//	if okErr == nil {
		//		return conn.(net.Conn), nil
		//	}
	}
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		if rawConn != nil {
			rawConn.Close()
		}
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}
	//////////////////

	spec, err := StringToSpec(rt.JA3, rt.UserAgent, rt.tlsExtensions, rt.forceHTTP1)
	if err != nil {
		return nil, err
	}

	rt.config.ServerName = host
	tlsConn := utls.UClient(rawConn, rt.config.Clone(), utls.HelloCustom)

	if err := tlsConn.ApplyPreset(spec); err != nil {
		if tlsConn != nil {
			tlsConn.Close()
		}
		return nil, err
	}

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			_ = tlsConn.Close()
			//fix this
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		} else if err == io.EOF {
			// 无需处理
		} else {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
		}

	}

	//////////
	_, ok := rt.cachedTransports.Load(addr)
	if ok {
		return tlsConn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN.
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		t2 := http2.Transport{
			DialTLS:         rt.dialTLSHTTP2,
			TLSClientConfig: rt.config,
		}
		if rt.http2Settings != nil {
			t2.HTTP2Settings = rt.http2Settings
		}
		rt.cachedTransports.Store(addr, &t2)
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.cachedTransports.Store(addr, &http.Transport{
			DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return rt.dialTLS(ctx, cancel, network, addr)
			},
			IdleConnTimeout: time.Duration(rt.Timeout) * time.Second,
		})

	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.cachedConnections.Set(addr, tlsConn)

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rt.Timeout)*time.Second)
	//defer cancel()
	return rt.dialTLS(ctx, cancel, network, addr)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func newRoundTripper(browser Browser, config *utls.Config, tlsExtensions *TLSExtensions, http2Settings *http2.HTTP2Settings, forceHTTP1 bool, timeout int, dialer ...proxy.ContextDialer) http.RoundTripper {
	if config == nil {
		if strings.Index(strings.Split(browser.JA3, ",")[2], "-41") == -1 {
			config = &utls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			config = &utls.Config{
				InsecureSkipVerify: true,
				SessionTicketKey:   [32]byte{},
				ClientSessionCache: utls.NewLRUClientSessionCache(0),
				OmitEmptyPsk:       true,
			}
		}
	}
	if len(dialer) > 0 {

		return &roundTripper{
			dialer: dialer[0],

			JA3:              browser.JA3,
			UserAgent:        browser.UserAgent,
			Timeout:          timeout,
			cachedTransports: sync.Map{},
			cachedConnections: gache.New(1).LFU().Expiration(time.Duration(timeout) * time.Second).EvictedFunc(func(key interface{}, v interface{}) {
				err := v.(net.Conn).Close()
				if err != nil {
					return
				}
			}).Build(),
			config:        config,
			tlsExtensions: tlsExtensions,
			http2Settings: http2Settings,
			forceHTTP1:    forceHTTP1,
		}
	}

	return &roundTripper{
		dialer: proxy.Direct,

		JA3:              browser.JA3,
		UserAgent:        browser.UserAgent,
		Timeout:          timeout,
		cachedTransports: sync.Map{},
		cachedConnections: gache.New(1).LFU().Expiration(time.Duration(timeout) * time.Second).EvictedFunc(func(key interface{}, v interface{}) {
			err := v.(net.Conn).Close()
			if err != nil {
				return
			}
		}).Build(),
		config:        config,
		tlsExtensions: tlsExtensions,
		http2Settings: http2Settings,
		forceHTTP1:    forceHTTP1,
	}
}
