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
	"github.com/xfali/noauth-proxy/pkg/token"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

const (
	CookieNameType = "sso-proxy-type"

	AuthTimeout            = 15 * time.Second
	DefaultTokenExpireTime = 2 * time.Hour
	DefaultHttpStatus      = http.StatusOK
)

type proxy struct {
	authentication auth.Authentication
	proxy          *httputil.ReverseProxy
}

type HandlerOpt func(*handler)

type handler struct {
	logger              log.LogFunc
	reverseProxyCreator reverseProxyCreator
	authMgr             auth.AuthenticatorManager
	verifier            auth.AuthorizationVerifier
	tokenMgr            token.Manager
	tokenExpireTime     time.Duration

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
		authMgr:             auth.DefaultAuthenticatorMgr,
		proxies:             map[string]*httputil.ReverseProxy{},
		reverseProxyCreator: defaultReverseProxyCreator,
		tokenExpireTime:     DefaultTokenExpireTime,
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func (h *handler) Prepare(w http.ResponseWriter, r *http.Request) {
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
		authentication, err := authenticator.ReadAuthentication(ctx, r)
		if err != nil {
			http.Error(w, "Read Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		err = authenticator.AttachAuthentication(ctx, w, authentication)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     CookieNameType,
			Value:    authType,
			Path:     "/",
			HttpOnly: true,
		})
		err = h.tryCreateProxy(authentication)
		if err != nil {
			http.Error(w, "Create Reverse Proxy failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Switch Only support POST method ", http.StatusBadRequest)
		return
	}
}

func (h *handler) Proxy(w http.ResponseWriter, r *http.Request) {
	if h.verifier != nil {
		if !h.verifier.Verify(w, r) {
			h.logger("Verify failed")
			return
		}
	}
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

func (h *handler) GenerateToken(w http.ResponseWriter, r *http.Request) {
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
		authentication, err := authenticator.ReadAuthentication(ctx, r)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		t, err := h.tokenMgr.Generate(ctx, authentication, time.Now().Add(h.tokenExpireTime))
		if err != nil {
			http.Error(w, "Get Token failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(t.Bytes())
	} else {
		http.Error(w, "Generate Token Only support POST method ", http.StatusBadRequest)
		return
	}
}

func (h *handler) Redirect(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		authType := r.URL.Query().Get("auth_type")
		if authType == "" {
			http.Error(w, "Auth type query param is empty", http.StatusBadRequest)
			return
		}
		authToken := r.URL.Query().Get("token")
		if authToken == "" {
			http.Error(w, "Token query param is empty", http.StatusBadRequest)
			return
		}
		redirectUrl := r.URL.Query().Get("redirect")
		if redirectUrl == "" {
			http.Error(w, "Redirect Url query param is empty", http.StatusBadRequest)
			return
		}
		redirectUrl, _ = url.QueryUnescape(redirectUrl)

		ctx := context.Background()
		authentication, err := h.tokenMgr.GetAuthentication(ctx, token.Token(authToken))
		if err != nil {
			http.Error(w, "GetAuthentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		authenticator, have := h.authMgr.GetAuthenticator(ctx, authType)
		if !have {
			http.Error(w, "Auth type not support: "+authType, http.StatusBadRequest)
			return
		}

		err = authenticator.AttachAuthentication(ctx, w, authentication)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		cookie := &http.Cookie{
			Name:     CookieNameType,
			Value:    authType,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		err = h.tryCreateProxy(authentication)
		if err != nil {
			http.Error(w, "Create Reverse Proxy failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		req := r.Clone(r.Context())
		req.AddCookie(cookie)
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
	} else {
		http.Error(w, "Redirect Only support GET method: ", http.StatusBadRequest)
		return
	}
}

func (h *handler) Close() error {
	if h.tokenMgr != nil {
		return h.tokenMgr.Close()
	}
	return nil
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

	h.proxies[key] = p
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

func (o handleOpts) SetAuthorizationVerifier(verifier auth.AuthorizationVerifier) HandlerOpt {
	return func(h *handler) {
		h.verifier = verifier
	}
}

func (o handleOpts) SetTokenManager(manager token.Manager) HandlerOpt {
	return func(h *handler) {
		h.tokenMgr = manager
	}
}

func (o handleOpts) SetTokenExpireTime(tokenExpireTime time.Duration) HandlerOpt {
	return func(h *handler) {
		h.tokenExpireTime = tokenExpireTime
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
	ret.code = DefaultHttpStatus
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
	r.code = DefaultHttpStatus
}

func (r *responseWriter) flush() error {
	r.ResponseWriter.WriteHeader(r.code)
	_, err := r.ResponseWriter.Write(r.buf.Bytes())
	return err
}
