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
	"github.com/xfali/noauth-proxy/pkg/auth"
	"github.com/xfali/noauth-proxy/pkg/log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

const (
	CookieNameType = "sso-proxy-type"

	AuthTimeout = 15 * time.Second
)

type proxy struct {
	authentication auth.Authentication
	proxy          *httputil.ReverseProxy
}

type HandlerOpt func(*handler)

type handler struct {
	logger              log.LogFunc
	authMgr             auth.AuthenticatorManager
	reverseProxyCreator reverseProxyCreator

	proxies   map[string]*httputil.ReverseProxy
	proxyLock sync.RWMutex
}

type reverseProxyCreator func(u *url.URL) *httputil.ReverseProxy

func defaultReverseProxyCreator(u *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(u)
	p.Transport = http.DefaultTransport
	return p
}

func NewHandler(logger log.LogFunc, opts ...HandlerOpt) *handler {
	ret := &handler{
		logger:              logger,
		proxies:             map[string]*httputil.ReverseProxy{},
		reverseProxyCreator: defaultReverseProxyCreator,
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func (h *handler) Switch(w http.ResponseWriter, r *http.Request) {
	authType := r.URL.Query().Get("auth_type")
	if authType == "" {
		http.Error(w, "Auth type query param is empty", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		ctx := context.Background()
		authenticator, have := h.authMgr.GetAuthenticator(ctx, authType)
		if !have {
			http.Error(w, "Auth type not support: "+authType, http.StatusBadRequest)
			return
		}
		authentication, err := authenticator.AttachAuthentication(ctx, w, r)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		err = h.tryCreateProxy(authentication)
		if err != nil {
			http.Error(w, "Create Reverse Proxy failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
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
	ctx, _ := context.WithTimeout(context.Background(), AuthTimeout)
	authenticator, have := h.authMgr.GetAuthenticator(ctx, authType)
	if !have || authenticator == nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, authType+" Not support ")))
		return
	}

	auth, err := authenticator.ExtractAuthentication(ctx, r)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, "Extract Authentication failed")))
		return
	}

	rp := h.getProxy(auth)
	req := r.Clone(r.Context())
	resp := newResponseWriter(w)
	defer resp.flush()

	auth.AttachToRequest(req)
	rp.ServeHTTP(resp, req)
	if resp.code == http.StatusUnauthorized {
		err = authenticator.Refresh(ctx, auth)
		if err != nil {
			h.logger("Refresh Authentication failed: %v \n", err)
			return
		}
		resp.reset()
		auth.AttachToRequest(req)
		rp.ServeHTTP(resp, req)
	}
}

func (h *handler) getProxy(authentication auth.Authentication) *httputil.ReverseProxy {
	h.proxyLock.RLock()
	defer h.proxyLock.RUnlock()

	return h.proxies[authentication.ID()]
}

func (h *handler) tryCreateProxy(authentication auth.Authentication) error {
	h.proxyLock.Lock()
	defer h.proxyLock.Unlock()

	key := authentication.ID()
	if v := h.proxies[key]; v != nil {
		return nil
	}
	addr := authentication.PassAddress()
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	p := h.reverseProxyCreator(u)

	h.proxies[authentication.ID()] = p
	return nil
}

type handleOpts struct {
}

var HandleOpts handleOpts

func (o handleOpts) ReverseProxyCreator(creator reverseProxyCreator) HandlerOpt {
	return func(h *handler) {
		h.reverseProxyCreator = creator
	}
}

func (o handleOpts) AuthenticatorManager(manager auth.AuthenticatorManager) HandlerOpt {
	return func(h *handler) {
		h.authMgr = manager
	}
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
