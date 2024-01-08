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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xfali/sso-proxy/pkg/encrypt"
	"net/http"
	"reflect"
)

const (
	CookieNamePayload = "sso-proxy-payload"
)

type defaultAuthenticator struct {
	authType reflect.Type
}

func NewAuthenticator() *defaultAuthenticator {
	ret := &defaultAuthenticator{}

	return ret
}

func (a *defaultAuthenticator) AttachAuthentication(ctx context.Context, resp http.ResponseWriter, auth Authentication) error {
	if m, ok := auth.(Marshaler); ok {
		t := reflect.TypeOf(auth)
		if a.authType != nil {
			if a.authType != t {
				return fmt.Errorf("Exists type %s not match target type %s ", a.authType.String(), t.String())
			}
		}
		d, err := m.AuthMarshal()
		if err != nil {
			return err
		}
		if a.authType == nil {
			a.authType = t
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
	return nil
}

func (a *defaultAuthenticator) ExtractAuthentication(ctx context.Context, req *http.Request) (Authentication, error) {
	if a.authType == nil {
		panic("Authentication type unknown ")
	}
	auth := reflect.New(a.authType).Elem().Interface()
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

type UsernamePasswordAuthentication struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`

	service encrypt.Service
}

func (a *UsernamePasswordAuthentication) WithEncrypt(service encrypt.Service) {
	if service == nil {
		a.service = encrypt.GlobalService()
	} else {
		a.service = service
	}
	u, _ := a.service.Encrypt([]byte(a.Username))
	a.Username = string(u)
	p, _ := a.service.Encrypt([]byte(a.Password))
	a.Password = string(p)
}

func (a *UsernamePasswordAuthentication) ID() string {
	return fmt.Sprintf("%s@[%s]%s://%s:%d", a.Username, a.Password, a.Protocol, a.Host, a.Port)
}

func (a *UsernamePasswordAuthentication) AttachToRequest(req *http.Request) {

}

func (a *UsernamePasswordAuthentication) Refresh(ctx context.Context) error {
	return nil
}

func (a *UsernamePasswordAuthentication) AuthMarshal() ([]byte, error) {
	return json.Marshal(a)
}

func (a *UsernamePasswordAuthentication) AuthUnmarshal(data []byte) error {
	return json.Unmarshal(data, a)
}
