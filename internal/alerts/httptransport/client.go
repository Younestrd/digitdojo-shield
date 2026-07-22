// Package httptransport centralizes outbound HTTP behavior for alert providers.
package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const UserAgent = "DigitDojo-Shield/1.0"

type Class string

const (
	Success              Class = "success"
	ClientError          Class = "client_error"
	AuthenticationFailed Class = "authentication_failed"
	AuthorizationFailed  Class = "authorization_failed"
	RateLimited          Class = "rate_limited"
	Timeout              Class = "timeout"
	NetworkUnreachable   Class = "network_unreachable"
	DNSFailure           Class = "dns_failure"
	TLSFailure           Class = "tls_failure"
	ServerError          Class = "server_error"
)

type Error struct {
	Class  Class
	Status int
	Err    error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.Class, e.Err) }
func (e *Error) Unwrap() error { return e.Err }
func (e *Error) Temporary() bool {
	return e.Class == RateLimited || e.Class == Timeout || e.Class == NetworkUnreachable || e.Class == DNSFailure || e.Class == ServerError
}

type Client struct{ http *http.Client }

func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 10
	transport.IdleConnTimeout = 90 * time.Second
	return &Client{http: &http.Client{Transport: transport, Timeout: timeout}}
}
func (c *Client) PostJSON(ctx context.Context, target string, headers map[string]string, payload any) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", UserAgent)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, classifyError(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, body, &Error{Class: classifyStatus(response.StatusCode), Status: response.StatusCode, Err: fmt.Errorf("HTTP %d", response.StatusCode)}
	}
	return response.StatusCode, body, nil
}
func classifyStatus(status int) Class {
	switch status {
	case 401:
		return AuthenticationFailed
	case 403:
		return AuthorizationFailed
	case 429:
		return RateLimited
	}
	if status >= 500 {
		return ServerError
	}
	return ClientError
}
func classifyError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Class: Timeout, Err: err}
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return &Error{Class: DNSFailure, Err: err}
	}
	var neterr net.Error
	if errors.As(err, &neterr) {
		if neterr.Timeout() {
			return &Error{Class: Timeout, Err: err}
		}
		return &Error{Class: NetworkUnreachable, Err: err}
	}
	if strings.Contains(strings.ToLower(err.Error()), "tls") {
		return &Error{Class: TLSFailure, Err: err}
	}
	var parse *url.Error
	if errors.As(err, &parse) {
		return &Error{Class: NetworkUnreachable, Err: err}
	}
	return &Error{Class: NetworkUnreachable, Err: err}
}
