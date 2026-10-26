package loopback

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// ErrRedirect reports a redirect URI that is not an explicit local HTTP
// listener. In particular, a configuration typo must never send authorization
// codes off-device.
var ErrRedirect = errors.New("the OAuth redirect URI must be an http loopback URL with an explicit port")

// ParseRedirect validates a native redirect URI: plain HTTP on a loopback host
// with an explicit port, an unambiguous path, and no user, query or fragment.
func ParseRedirect(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") || !strings.HasPrefix(u.Path, "/") || u.RawPath != "" || u.Opaque != "" {
		return nil, ErrRedirect
	}
	host := u.Hostname()
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	port, portErr := strconv.Atoi(u.Port())
	if !loopback || portErr != nil || port < 1 || port > 65535 {
		return nil, ErrRedirect
	}
	return u, nil
}

type listenAddress struct {
	network, address string
	// Optional addresses may be unavailable, such as IPv6 loopback on a host
	// without IPv6; the callback then listens on the required address only.
	optional bool
}

// A localhost callback may resolve to either loopback family, so both are
// served. Literal IP callbacks listen only on that address.
func listenAddresses(u *url.URL) []listenAddress {
	host, port := u.Hostname(), u.Port()
	if host == "localhost" {
		return []listenAddress{{network: "tcp4", address: net.JoinHostPort("127.0.0.1", port)}, {network: "tcp6", address: net.JoinHostPort("::1", port), optional: true}}
	}
	network := "tcp4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "tcp6"
	}
	return []listenAddress{{network: network, address: net.JoinHostPort(host, port)}}
}

// Listen opens the callback listener for a redirect URI returned by
// ParseRedirect.
func Listen(u *url.URL) (net.Listener, error) {
	var listeners []net.Listener
	for _, candidate := range listenAddresses(u) {
		listener, err := net.Listen(candidate.network, candidate.address)
		if err != nil {
			if candidate.optional {
				continue
			}
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 1 {
		return listeners[0], nil
	}
	return newMultiListener(listeners), nil
}

// multiListener accepts connections from several listeners as one, so a single
// http.Server and a single Close cover every loopback family.
type multiListener struct {
	listeners []net.Listener
	conns     chan net.Conn
	done      chan struct{}
	once      sync.Once
}

func newMultiListener(listeners []net.Listener) *multiListener {
	m := &multiListener{listeners: listeners, conns: make(chan net.Conn), done: make(chan struct{})}
	for _, listener := range listeners {
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				select {
				case m.conns <- conn:
				case <-m.done:
					_ = conn.Close()
					return
				}
			}
		}()
	}
	return m
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.conns:
		return conn, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	m.once.Do(func() {
		close(m.done)
		for _, listener := range m.listeners {
			_ = listener.Close()
		}
	})
	return nil
}

func (m *multiListener) Addr() net.Addr {
	return m.listeners[0].Addr()
}
