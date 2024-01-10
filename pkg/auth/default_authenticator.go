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
	"github.com/xfali/noauth-proxy/pkg/encrypt"
	"io"
	"net/http"
	"reflect"
)

var (
	CookieNamePayload = "sso-proxy-payload"
)

type defaultAuthenticationFactory struct {
	authType      reflect.Type
	isPointer     bool
	authElemType  reflect.Type
	elemIsPointer bool
}

func NewAuthenticationFactory(o Authentication, e AuthenticationElements) *defaultAuthenticationFactory {
	t := reflect.TypeOf(o)
	isPtr := false
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		isPtr = true
	}
	ret := &defaultAuthenticationFactory{
		authType:  t,
		isPointer: isPtr,
	}
	t = reflect.TypeOf(e)
	isPtr = false
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		isPtr = true
	}
	ret.authElemType = t
	ret.elemIsPointer = isPtr
	return ret
}

func (f *defaultAuthenticationFactory) NewAuthentication(req *http.Request) Authentication {
	rv := reflect.New(f.authType)
	if !f.isPointer {
		rv = rv.Elem()
	}
	return rv.Interface().(Authentication)
}

func (f *defaultAuthenticationFactory) NewAuthenticationElements(req *http.Request) AuthenticationElements {
	rv := reflect.New(f.authElemType)
	if !f.elemIsPointer {
		rv = rv.Elem()
	}
	return rv.Interface().(AuthenticationElements)
}

type defaultAuthenticator struct {
	factory    AuthenticationFactory
	refresher  AuthenticationRefresher
	encryptSvc encrypt.Service
}

func NewAuthenticator(factory AuthenticationFactory, refresher AuthenticationRefresher) *defaultAuthenticator {
	ret := &defaultAuthenticator{
		factory:    factory,
		encryptSvc: encrypt.GlobalService(),
	}
	if refresher != nil {
		ret.refresher = refresher
	}
	return ret
}

func (a *defaultAuthenticator) newAuthentication(req *http.Request) Authentication {
	v := a.factory.NewAuthentication(req)
	v.SetEncrypt(a.encryptSvc)
	return v
}

func (a *defaultAuthenticator) newAuthenticationElements(req *http.Request) AuthenticationElements {
	v := a.factory.NewAuthenticationElements(req)
	v.SetEncrypt(a.encryptSvc)
	return v
}

func (a *defaultAuthenticator) SetEncrypt(service encrypt.Service) {
	a.encryptSvc = service
}

func (a *defaultAuthenticator) ReadAuthentication(ctx context.Context, req *http.Request) (Authentication, error) {
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

func (a *defaultAuthenticator) AttachAuthenticationElement(ctx context.Context, resp http.ResponseWriter, auth Authentication) error {
	authElem, err := a.refresher.CreateAuthenticationElements(ctx, auth)
	if err != nil {
		return err
	}
	var d []byte
	if m, ok := authElem.(Marshaler); ok {
		d, err = m.AuthMarshal()
		if err != nil {
			return err
		}
	} else {
		d, err = json.Marshal(authElem)
		if err != nil {
			return err
		}
	}
	cookieData := base64.StdEncoding.EncodeToString(d)
	cookie := &http.Cookie{
		Name:     CookieNamePayload,
		Value:    cookieData,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(resp, cookie)
	return nil
}

func (a *defaultAuthenticator) ExtractAuthenticationElement(ctx context.Context, req *http.Request) (AuthenticationElements, error) {
	auth := a.newAuthenticationElements(req)
	c, err := req.Cookie(CookieNamePayload)
	if err != nil {
		return nil, err
	}
	if c.Value == "" {
		return nil, errors.New("Cookie is invalid ")
	}
	v, _ := base64.StdEncoding.DecodeString(c.Value)
	if m, ok := auth.(Unmarshaler); ok {
		err = m.AuthUnmarshal(v)
		if err != nil {
			return nil, err
		}
		return m.(AuthenticationElements), nil
	} else {
		err = json.Unmarshal(v, auth)
		if err != nil {
			return nil, err
		}
		return auth, nil
	}
	//return nil, errors.New("Not support AuthenticationElements type ")
}

func (a *defaultAuthenticator) Refresh(ctx context.Context, authentication AuthenticationElements) error {
	if a.refresher != nil {
		return a.refresher.Refresh(ctx, authentication)
	}
	return errors.New("Authentication Refresher not set ")
}

func (a *defaultAuthenticator) CreateAuthenticationElements(ctx context.Context, auth Authentication) (AuthenticationElements, error) {
	if a.refresher != nil {
		return a.refresher.CreateAuthenticationElements(ctx, auth)
	}
	return nil, errors.New("Authentication Refresher not set ")
}

type UsernamePasswordAuthentication struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`

	service encrypt.Service
}

func (a *UsernamePasswordAuthentication) SetEncrypt(service encrypt.Service) {
	if service == nil {
		a.service = encrypt.GlobalService()
	} else {
		a.service = service
	}
	//u, _ := a.service.Encrypt([]byte(a.Username))
	//a.Username = string(u)
	//p, _ := a.service.Encrypt([]byte(a.Password))
	//a.Password = string(p)
}

func (a *UsernamePasswordAuthentication) PassAddress() string {
	return fmt.Sprintf("%s://%s:%d", a.Protocol, a.Host, a.Port)
}

func (a *UsernamePasswordAuthentication) Key() string {
	return fmt.Sprintf("%s@[%s]%s://%s:%d", a.Username, a.Password, a.Protocol, a.Host, a.Port)
}

func (a *UsernamePasswordAuthentication) AuthMarshal() ([]byte, error) {
	v := *a
	u, _ := a.service.Encrypt([]byte(a.Username))
	p, _ := a.service.Encrypt([]byte(a.Password))
	v.Username = base64.StdEncoding.EncodeToString(u)
	v.Password = base64.StdEncoding.EncodeToString(p)
	return json.Marshal(v)
}

func (a *UsernamePasswordAuthentication) AuthUnmarshal(data []byte) error {
	err := json.Unmarshal(data, a)
	if err != nil {
		return err
	}
	du, _ := base64.StdEncoding.DecodeString(a.Username)
	dp, _ := base64.StdEncoding.DecodeString(a.Password)
	u, _ := a.service.Decrypt(du)
	p, _ := a.service.Decrypt(dp)

	a.Username = string(u)
	a.Password = string(p)
	return nil
}
