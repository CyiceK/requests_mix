package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	http "github.com/CyiceK/chttp-mix"
	http2 "github.com/CyiceK/chttp-mix/http2"
	gache "github.com/bluele/gcache"
	cmap "github.com/orcaman/concurrent-map/v2"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.RWMutex
	// fix typing
	JA3       string
	UserAgent string
	Timeout   time.Duration // time.Second

	cachedConnections      gache.Cache
	cachedTransports       cmap.ConcurrentMap[string, http.RoundTripper]
	cachedTransportsLocker sync.Mutex
	//cachedConnections sync.Map
	//cachedTransports sync.Map

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

func (rt *roundTripper) storeTs(addr string, ts any) {
	rt.cachedTransportsLocker.Lock()
	defer rt.cachedTransportsLocker.Unlock()
	if rt.cachedTransports.Has(addr) {
		return
	}
	if trH2, ok := ts.(*http2.Transport); ok {
		rt.cachedTransports.Set(addr, trH2)
	} else if trH1, ok := ts.(*http.Transport); ok {
		rt.cachedTransports.Set(addr, trH1)
	} else {
		return
	}
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) (http.RoundTripper, error) {
	if tr, existTr := rt.cachedTransports.Get(addr); existTr {
		return tr, nil
	}
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		ts := &http.Transport{
			DialContext:       rt.dialer.DialContext,
			DisableKeepAlives: true,
			IdleConnTimeout:   rt.Timeout,
		}
		rt.storeTs(addr, ts)
		return ts, nil
	case "https":
		if rt.forceHTTP1 {
			ts := &http.Transport{
				DialContext: rt.dialer.DialContext,
				DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
					newCtx, cancel := context.WithTimeout(ctx, rt.Timeout)
					return rt.dialTLS(newCtx, cancel, network, addr)
				},
				IdleConnTimeout: rt.Timeout,
			}
			rt.storeTs(addr, ts)
			return ts, nil
		} else {
			switch req.Proto {
			case "HTTP/2.0":
				var http2Settings *http2.HTTP2Settings
				if rt.http2Settings != nil {
					http2Settings = rt.http2Settings
				} else {
					http2Settings = nil
				}
				ts := &http2.Transport{
					DialTLS:         rt.dialTLSHTTP2,
					TLSClientConfig: rt.config,
					HTTP2Settings:   http2Settings,
				}
				rt.storeTs(addr, ts)
				return ts, nil
			default: // "HTTP/1.1" "HTTP/1.0"
				ts := &http.Transport{
					DialContext: rt.dialer.DialContext,
					DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
						newCtx, cancel := context.WithTimeout(ctx, rt.Timeout)
						return rt.dialTLS(newCtx, cancel, network, addr)
					},
					IdleConnTimeout: rt.Timeout,
				}
				rt.storeTs(addr, ts)
				return ts, nil
			}
		}
	default:
		return nil, fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}
}

func (rt *roundTripper) dialTLS(ctx context.Context, cancel context.CancelFunc, network, addr string) (net.Conn, error) {
	// 确保在访问共享资源时使用锁
	rt.Lock()
	defer rt.Unlock()

	//defer cancel()
	defer ctx.Done()

	// 检查缓存连接
	conn, okErr := rt.cachedConnections.Get(addr)
	if okErr == nil {
		return conn.(net.Conn), nil
	}

	// 建立新的连接
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
		rawConn.Close() // 确保在错误时关闭连接
		return nil, err
	}

	rt.config.ServerName = host
	tlsConn := utls.UClient(rawConn, rt.config.Clone(), utls.HelloCustom)
	if err = tlsConn.ApplyPreset(spec); err != nil {
		if tlsConn != nil {
			tlsConn.Close()
		}
		return nil, err
	}

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		}
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = tlsConn.SetDeadline(time.Now().Add(rt.Timeout))
	if err != nil {
		return nil, err
	}

	//////////

	// 缓存新的连接
	if rt.cachedConnections.Has(addr) {
		conn, okErr = rt.cachedConnections.Get(addr)
		if okErr == nil {
			err = conn.(net.Conn).Close()
			if err != nil {
				tlsConn.Close() // 确保在错误时关闭新建立的连接
				return nil, err
			}
		}
	}
	rt.cachedConnections.Set(addr, tlsConn)
	return tlsConn, nil
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rt.Timeout)
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

func newRoundTripper(browser Browser, config *utls.Config, tlsExtensions *TLSExtensions, http2Settings *http2.HTTP2Settings, forceHTTP1 bool, timeout time.Duration, dialer ...proxy.ContextDialer) http.RoundTripper {
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
			cachedTransports: cmap.New[http.RoundTripper](),
			cachedConnections: gache.New(10).LFU().Expiration(time.Second * 3).EvictedFunc(func(key interface{}, v interface{}) {
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
		cachedTransports: cmap.New[http.RoundTripper](),
		cachedConnections: gache.New(10).LFU().Expiration(time.Second * 3).EvictedFunc(func(key interface{}, v interface{}) {
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
