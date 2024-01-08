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

const (
	CookieNamePayload = "sso-proxy-payload"
)

type defaultAuthenticator struct {
	authType   reflect.Type
	isPointer  bool
	encryptSvc encrypt.Service
}

func NewAuthenticator(o Authentication) *defaultAuthenticator {
	t := reflect.TypeOf(o)
	isPtr := false
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		isPtr = true
	}
	ret := &defaultAuthenticator{
		authType:   t,
		isPointer:  isPtr,
		encryptSvc: encrypt.GlobalService(),
	}

	return ret
}

func (a *defaultAuthenticator) newAuthentication() Authentication {
	rv := reflect.New(a.authType)
	if !a.isPointer {
		rv = rv.Elem()
	}
	v := rv.Interface().(Authentication)
	v.SetEncrypt(a.encryptSvc)
	return v
}

func (a *defaultAuthenticator) SetEncrypt(service encrypt.Service) {
	a.encryptSvc = service
}

func (a *defaultAuthenticator) AttachAuthentication(ctx context.Context, resp http.ResponseWriter, req *http.Request) (Authentication, error) {
	body := req.Body
	defer body.Close()

	buf := &bytes.Buffer{}
	_, err := io.Copy(buf, body)
	if err != nil {
		return nil, err
	}
	auth := a.newAuthentication()
	if m, ok := auth.(Unmarshaler); ok {
		err = m.AuthUnmarshal(buf.Bytes())
		if err != nil {
			return nil, err
		}
	}
	if m, ok := auth.(Marshaler); ok {
		d, err := m.AuthMarshal()
		if err != nil {
			return nil, err
		}
		cookieData := base64.StdEncoding.EncodeToString(d)
		cookie := &http.Cookie{
			Name:     CookieNamePayload,
			Value:    cookieData,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(resp, cookie)
	}
	return auth, nil
}

func (a *defaultAuthenticator) ExtractAuthentication(ctx context.Context, req *http.Request) (Authentication, error) {
	if a.authType == nil {
		panic("Authentication type unknown ")
	}
	auth := a.newAuthentication()
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
		return m.(Authentication), nil
	}
	return nil, errors.New("Not support Authentication type ")
}

func (a *defaultAuthenticator) Refresh(ctx context.Context, authentication Authentication) error {
	return authentication.Refresh(ctx)
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

func (a *UsernamePasswordAuthentication) ID() string {
	return fmt.Sprintf("%s@[%s]%s://%s:%d", a.Username, a.Password, a.Protocol, a.Host, a.Port)
}

func (a *UsernamePasswordAuthentication) AttachToRequest(req *http.Request) {
	panic("Not Implement")
}

func (a *UsernamePasswordAuthentication) Refresh(ctx context.Context) error {
	panic("Not Implement")
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
