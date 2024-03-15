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

package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xfali/noauth-proxy/pkg/clock"
	"github.com/xfali/noauth-proxy/pkg/encrypt"
	"github.com/xfali/noauth-proxy/pkg/token"
	"io"
	"net/http"
	"time"
)

type tokenAuthenticator struct {
	factory      AuthenticationFactory
	refresher    AuthenticationRefresher
	elemNotifier AuthenticationElementsCreateNotifier
	manager      token.Manager
	encryptSvc   encrypt.Service
	respModifier ResponseModifier

	tokenExpireTime time.Duration
}

type tokenAuthData struct {
	auth     Authentication
	authElem AuthenticationElements
}

func NewAuthenticator(factory AuthenticationFactory, refresher AuthenticationRefresher, opts ...tokenAuthenticatorOpt) *tokenAuthenticator {
	ret := &tokenAuthenticator{
		factory:    factory,
		manager:    token.NewManager(token.ManagerOpts.Filter(token.NewMapFilter())),
		encryptSvc: encrypt.GlobalService(),
	}
	if refresher != nil {
		ret.refresher = refresher
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func (a *tokenAuthenticator) Close() error {
	return a.manager.Close()
}

func (a *tokenAuthenticator) newAuthentication(req *http.Request) Authentication {
	v := a.factory.NewAuthentication(req)
	v.SetEncrypt(a.encryptSvc)
	return v
}

func (a *tokenAuthenticator) newAuthenticationElements(req *http.Request) AuthenticationElements {
	v := a.factory.NewAuthenticationElements(req)
	v.SetEncrypt(a.encryptSvc)
	return v
}

func (a *tokenAuthenticator) SetEncrypt(service encrypt.Service) {
	a.encryptSvc = service
}

func (a *tokenAuthenticator) Modify(resp *http.Response, authentication Authentication) error {
	if a.respModifier != nil {
		return a.respModifier.Modify(resp, authentication)
	}
	return nil
}

func (a *tokenAuthenticator) ReadAuthentication(ctx context.Context, req *http.Request) (Authentication, error) {
	body := req.Body
	defer body.Close()

	buf := &bytes.Buffer{}
	_, err := io.Copy(buf, body)
	if err != nil {
		return nil, err
	}
	auth := a.newAuthentication(req)
	if m, ok := auth.(Unmarshaler); ok {
		err = m.AuthUnmarshal(buf.Bytes())
		if err != nil {
			return nil, err
		}
	} else {
		err = json.Unmarshal(buf.Bytes(), auth)
		if err != nil {
			return nil, err
		}
	}
	return auth, nil
}

func (a *tokenAuthenticator) AttachAuthenticationElement(ctx context.Context, resp http.ResponseWriter, auth Authentication) error {
	attacher, err := a.CreateAuthenticationElementAttacher(ctx, auth)
	if err != nil {
		return err
	}
	attacher.AttachToResponse(resp)
	return nil
}

func (a *tokenAuthenticator) CreateAuthenticationElementAttacher(ctx context.Context, auth Authentication) (ResponseAttacher, error) {
	authElem, err := a.refresher.CreateAuthenticationElements(ctx, auth)
	if err != nil {
		return nil, err
	}
	if a.elemNotifier != nil {
		err = a.elemNotifier.AuthenticationElementsCreated(ctx, auth, authElem)
		if err != nil {
			return nil, err
		}
	}

	tokenValue, err := a.manager.Generate(ctx, &tokenAuthData{
		auth:     auth,
		authElem: NewAuthenticationElementsTokenWrapper(authElem),
	}, a.expireTime())
	if err != nil {
		return nil, fmt.Errorf("Attach Authentication Element with token failed: %v ", err)
	}
	t := base64.StdEncoding.EncodeToString(tokenValue.Bytes())
	return NewDetectableResponseAttacherWithFunc(func(resp http.ResponseWriter) {
		cookie := &http.Cookie{
			Name:  CookieNamePayload,
			Value: t,
			Path:  "/",
		}
		http.SetCookie(resp, cookie)
		if attcher, ok := authElem.(ResponseAttacher); ok {
			attcher.AttachToResponse(resp)
		}
	}, func() bool {
		d, cErr := a.manager.Get(context.Background(), tokenValue)
		return cErr == nil && d != nil
	}), nil
}

func (a *tokenAuthenticator) ExtractAuthenticationElement(ctx context.Context, req *http.Request) (AuthenticationElements, error) {
	c, err := req.Cookie(CookieNamePayload)
	if err != nil {
		return nil, err
	}
	if c.Value == "" {
		return nil, errors.New("Cookie is invalid ")
	}
	v, _ := base64.StdEncoding.DecodeString(c.Value)
	data, err := a.manager.Get(ctx, token.FromString(string(v)))
	if err != nil {
		return nil, fmt.Errorf("Extract Authentication Element with token failed: %v ", err)
	}
	return data.(*tokenAuthData).authElem, nil
	//return nil, errors.New("Not support AuthenticationElements type ")
}

func (a *tokenAuthenticator) Refresh(ctx context.Context, resp http.ResponseWriter, authentication AuthenticationElements) (AuthenticationElements, error) {
	if a.refresher != nil {
		//if err := a.refresher.Refresh(ctx, authentication); err == nil {
		//	return nil
		//}
		wrapper := authentication.(*AuthenticationElementsTokenWrapper)
		d, err := a.manager.Get(ctx, wrapper.token)
		if err != nil {
			return nil, err
		}
		authData := d.(*tokenAuthData)

		elem, err := a.refresher.CreateAuthenticationElements(ctx, authData.auth)
		if err != nil {
			return nil, err
		}

		authData.authElem = NewAuthenticationElementsTokenWrapper(elem)
		err = a.manager.Set(ctx, wrapper.token, authData, a.expireTime(), token.SetFlagNone)

		if a.elemNotifier != nil {
			return elem, a.elemNotifier.AuthenticationElementsCreated(ctx, authData.auth, elem)
		}
		return elem, nil
	}
	return nil, errors.New("Authentication Refresher not set ")
}

func (a *tokenAuthenticator) expireTime() time.Time {
	if a.tokenExpireTime > 0 {
		return clock.Now().Add(a.tokenExpireTime)
	}
	return time.Time{}
}

func (d *tokenAuthData) Key() string {
	return d.auth.Key()
}

func (d *tokenAuthData) Set(t token.Token) {
	d.authElem.(*AuthenticationElementsTokenWrapper).Set(t)
}

type tokenAuthenticatorOpt func(*tokenAuthenticator)

type tokenAuthenticatorOpts struct {
}

var TokenAuthenticatorOpts tokenAuthenticatorOpts

func (o tokenAuthenticatorOpts) TokenManager(manager token.Manager) tokenAuthenticatorOpt {
	return func(authenticator *tokenAuthenticator) {
		if authenticator.manager != nil {
			_ = authenticator.manager.Close()
		}
		authenticator.manager = manager
	}
}

func (o tokenAuthenticatorOpts) TokenExpireTime(tokenExpireTime time.Duration) tokenAuthenticatorOpt {
	return func(authenticator *tokenAuthenticator) {
		authenticator.tokenExpireTime = tokenExpireTime
	}
}

func (o tokenAuthenticatorOpts) Modifier(modifyFunc ResponseModifier) tokenAuthenticatorOpt {
	return func(authenticator *tokenAuthenticator) {
		authenticator.respModifier = modifyFunc
	}
}

func (o tokenAuthenticatorOpts) AttachNotifier(notifier AuthenticationElementsCreateNotifier) tokenAuthenticatorOpt {
	return func(authenticator *tokenAuthenticator) {
		authenticator.elemNotifier = notifier
	}
}

type DetectableResponseAttacherFunc struct {
	AttachFunc func(resp http.ResponseWriter)
	CheckFunc  func() bool
}

func NewDetectableResponseAttacherWithFunc(attachFunc func(resp http.ResponseWriter), checkFunc func() bool) *DetectableResponseAttacherFunc {
	return &DetectableResponseAttacherFunc{
		AttachFunc: attachFunc,
		CheckFunc:  checkFunc,
	}
}

func (r *DetectableResponseAttacherFunc) AttachToResponse(resp http.ResponseWriter) {
	r.AttachFunc(resp)
}

func (r *DetectableResponseAttacherFunc) IsValid() bool {
	return r.CheckFunc()
}

type ResponseAttachFunc func(resp http.ResponseWriter)

func (r ResponseAttachFunc) AttachToResponse(resp http.ResponseWriter) {
	r(resp)
}

type TokenTouchedPolicy struct {
}

func (p *TokenTouchedPolicy) OnExpire(token token.Token) bool {
	return false
}

func (p *TokenTouchedPolicy) OnTouch(token token.Token) bool {
	return false
}
