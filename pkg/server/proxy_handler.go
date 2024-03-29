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
	"context"
	"fmt"
	"github.com/xfali/noauth-proxy/pkg/auth"
	"github.com/xfali/noauth-proxy/pkg/errs"
	"github.com/xfali/noauth-proxy/pkg/log"
	"github.com/xfali/noauth-proxy/pkg/token"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

const (
	AuthTimeout               = 15 * time.Second
	DefaultTokenExpireTime    = 2 * time.Hour
	DefaultHttpStatus         = http.StatusOK
	DefaultRedirectHttpStatus = http.StatusSeeOther
)

var (
	CookieNameType = "sso-proxy-type"
)

type proxy struct {
	authentication auth.Authentication
	proxy          *httputil.ReverseProxy
}

type HandlerOpt func(*handler)
type ResponseWrapCreator func() ResponseWriterWrapper

type attacherData struct {
	attacher   auth.ResponseAttacher
	expireTime time.Time
}

type handler struct {
	logger              log.LogFunc
	reverseProxyCreator reverseProxyCreator
	responseWrapCreator ResponseWrapCreator
	authMgr             auth.AuthenticatorManager
	verifier            auth.AuthorizationVerifier
	tokenMgr            token.Manager
	tokenExpireTime     time.Duration
	redirectHttpStatus  int

	attacherExpireTime time.Duration
	attachers          map[string]*attacherData
	attachLock         sync.RWMutex

	proxies   map[string]*httputil.ReverseProxy
	proxyLock sync.RWMutex
}

type reverseProxyCreator func(u *url.URL) *httputil.ReverseProxy

func NewHandler(logger log.LogFunc, opts ...HandlerOpt) *handler {
	ret := &handler{
		logger:              logger,
		authMgr:             auth.DefaultAuthenticatorMgr,
		attachers:           map[string]*attacherData{},
		proxies:             map[string]*httputil.ReverseProxy{},
		reverseProxyCreator: DefaultReverseProxyCreator,
		responseWrapCreator: DefaultResponseWriter,
		tokenExpireTime:     DefaultTokenExpireTime,
		redirectHttpStatus:  DefaultRedirectHttpStatus,
		tokenMgr:            token.NewManager(token.ManagerOpts.RevocationPolicy(&TokenTouchedPolicy{})),
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
		err = authenticator.AttachAuthenticationElement(ctx, w, authentication)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  CookieNameType,
			Value: authType,
			Path:  "/",
		})
		err = h.tryCreateProxy(authentication, authenticator)
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

	authElm, err := authenticator.ExtractAuthenticationElement(ctx, r)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, "Extract Authentication failed")))
		return
	}

	rp := h.getProxy(authElm)
	if rp == nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(BadGatewayHtml, "Upstream not found")))
		return
	}
	req := r.Clone(r.Context())
	resp := h.responseWrapCreator()
	defer resp.DoFlush()
	resp.Reset(w)

	authElm.AttachToRequest(req)
	rp.ServeHTTP(resp, req)
	if resp.HttpStatus() == http.StatusUnauthorized {
		authElm, err = authenticator.Refresh(ctx, resp, authElm)
		if err != nil {
			h.logger("Refresh Authentication failed: %v \n", err)
			return
		}
		resp.Reset(w)
		authElm.AttachToRequest(req)
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
		attacher := h.getResponseAttacher(authentication)
		// Check attacher is valid
		if attacher != nil {
			invalid := false
			if datt, ok := attacher.(auth.DetectableResponseAttacher); ok {
				if !datt.IsValid() {
					invalid = true
				}
			}
			if !invalid {
				_, _ = w.Write(t.Bytes())
				return
			}
		}
		attacher, err = authenticator.CreateAuthenticationElementAttacher(ctx, authentication)
		if err != nil {
			http.Error(w, "Attach Authentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		err = h.tryCreateResponseAttacher(authentication, attacher)
		if err != nil {
			http.Error(w, "Create Response Attacher failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		err = h.tryCreateProxy(authentication, authenticator)
		if err != nil {
			http.Error(w, "Create Reverse Proxy failed: "+err.Error(), http.StatusBadRequest)
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
		data, err := h.tokenMgr.Get(ctx, token.Token(authToken))
		if err != nil {
			http.Error(w, "GetAuthentication failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		authentication := data.(auth.Authentication)

		attacher := h.getResponseAttacher(authentication)
		if attacher == nil {
			http.Error(w, "Get Authentication failed: nil", http.StatusUnauthorized)
			return
		}

		attacher.AttachToResponse(w)

		cookie := &http.Cookie{
			Name:  CookieNameType,
			Value: authType,
			Path:  "/",
		}
		http.SetCookie(w, cookie)

		req := r.Clone(r.Context())
		req.AddCookie(cookie)
		http.Redirect(w, req, redirectUrl, h.redirectHttpStatus)
	} else {
		http.Error(w, "Redirect Only support GET method: ", http.StatusBadRequest)
		return
	}
}

func (h *handler) Close() error {
	var errList errs.ErrorList
	if h.tokenMgr != nil {
		err := h.tokenMgr.Close()
		if err != nil {
			_ = errList.Add(err)
		}
	}
	err := h.authMgr.Close()
	if err != nil {
		_ = errList.Add(err)
	}
	if errList.Empty() {
		return nil
	}
	return errList
}

func (h *handler) getResponseAttacher(authentication auth.Authentication) auth.ResponseAttacher {
	h.attachLock.RLock()
	defer h.attachLock.RUnlock()

	key := authentication.Key()
	v := h.attachers[key]
	if v == nil {
		return nil
	}
	if h.attacherExpireTime > 0 {
		if time.Now().Before(v.expireTime) {
			return v.attacher
		} else {
			delete(h.attachers, key)
			return nil
		}
	}
	return v.attacher
}

func (h *handler) tryCreateResponseAttacher(authentication auth.Authentication, attacher auth.ResponseAttacher) error {
	h.attachLock.Lock()
	defer h.attachLock.Unlock()

	key := authentication.Key()
	v := &attacherData{
		attacher: attacher,
	}
	if h.attacherExpireTime > 0 {
		v.expireTime = time.Now().Add(h.attacherExpireTime)
	}
	h.attachers[key] = v
	return nil
}

func (h *handler) getProxy(authentication auth.AuthenticationElements) *httputil.ReverseProxy {
	h.proxyLock.RLock()
	defer h.proxyLock.RUnlock()

	return h.proxies[authentication.Key()]
}

func (h *handler) tryCreateProxy(authentication auth.Authentication, authenticator auth.Authenticator) error {
	h.proxyLock.Lock()
	defer h.proxyLock.Unlock()

	key := authentication.Key()
	if v := h.proxies[key]; v != nil {
		return nil
	}
	addr := authentication.PassAddress()
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	p := h.reverseProxyCreator(u)
	if m, ok := authenticator.(auth.ResponseModifier); ok {
		p.ModifyResponse = func(response *http.Response) error {
			return m.Modify(response, authentication)
		}
	}

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

func (o handleOpts) ResponseWrapperCreator(creator ResponseWrapCreator) HandlerOpt {
	return func(h *handler) {
		h.responseWrapCreator = creator
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

func (o handleOpts) SetRedirectHttpStatus(redirectHttpStatus int) HandlerOpt {
	return func(h *handler) {
		h.redirectHttpStatus = redirectHttpStatus
	}
}

func (o handleOpts) SetAttacherExpireTime(attachersExpireTime time.Duration) HandlerOpt {
	return func(h *handler) {
		h.attacherExpireTime = attachersExpireTime
	}
}

type TokenTouchedPolicy struct {
}

func (p *TokenTouchedPolicy) OnExpire(token token.Token) bool {
	return true
}

func (p *TokenTouchedPolicy) OnTouch(token token.Token) bool {
	return true
}
