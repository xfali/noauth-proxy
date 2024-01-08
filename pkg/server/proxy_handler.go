/*
 * Copyright (C) 2024, Xiongfa Li.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"fmt"
	"github.com/xfali/sso-proxy/pkg/auth"
	"github.com/xfali/sso-proxy/pkg/log"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

const (
	CookieNameType    = "sso-proxy-type"
	CookieNamePayload = "sso-proxy-payload"

	AuthTimeout = 15 * time.Second
)

type proxy struct {
	authenticator auth.Authenticator
	proxy         *httputil.ReverseProxy
}

type handler struct {
	logger    log.LogFunc
	authMgr   auth.AuthenticatorManager
	transport http.RoundTripper

	proxies   map[string]*proxy
	proxyLock sync.RWMutex
}

func NewHandler(logger log.LogFunc) *handler {
	ret := &handler{
		logger:  logger,
		proxies: map[string]*proxy{},
	}
	return ret
}

func (h *handler) Switch(w http.ResponseWriter, r *http.Request) {

}

func (h *handler) Proxy(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(CookieNameType)
	if err != nil || c == nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, err)))
		return
	}
	authType := c.Value
	px := h.getProxy(authType)
	if px == nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, authType+" Not support ")))
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), AuthTimeout)

	auth, err := px.authenticator.ExtractAuthentication(ctx, r)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, "Extract Authentication failed")))
		return
	}

	req := r.Clone(r.Context())
	resp := newResponseWriter(w)
	defer resp.flush()

	auth.AttachToRequest(req)
	px.proxy.ServeHTTP(resp, req)
	if resp.code == http.StatusUnauthorized {
		err = auth.Refresh(ctx)
		if err != nil {
			h.logger("Refresh Authentication failed: %v \n", err)
			return
		}
		resp.reset()
		auth.AttachToRequest(req)
		px.proxy.ServeHTTP(resp, req)
	}
}

func (h *handler) getProxy(authType string) *proxy {
	h.proxyLock.RLock()
	defer h.proxyLock.RUnlock()

	return h.proxies[authType]
}

type responseWriter struct {
	http.ResponseWriter
	buf  bytes.Buffer
	code int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	ret := responseWriter{}
	ret.ResponseWriter = w
	return &ret
}

func (r *responseWriter) WriteHeader(statusCode int) {
	r.code = statusCode
	//r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseWriter) Write(d []byte) (int, error) {
	return r.buf.Write(d)
}

func (r *responseWriter) WriteString(d string) (int, error) {
	return r.buf.WriteString(d)
}

func (r *responseWriter) reset() {
	r.buf.Reset()
}

func (r *responseWriter) flush() error {
	r.ResponseWriter.WriteHeader(r.code)
	_, err := r.ResponseWriter.Write(r.buf.Bytes())
	return err
}
