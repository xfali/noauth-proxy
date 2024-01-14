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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/xfali/noauth-proxy/pkg/encrypt"
	"github.com/xfali/noauth-proxy/pkg/token"
)

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

type AuthenticationElementsTokenWrapper struct {
	AuthenticationElements
	token token.Token
}

func NewAuthenticationElementsTokenWrapper(elements AuthenticationElements) *AuthenticationElementsTokenWrapper {
	ret := &AuthenticationElementsTokenWrapper{}
	ret.AuthenticationElements = elements
	return ret
}

func (w *AuthenticationElementsTokenWrapper) Set(token2 token.Token) {
	w.token = token2
}

type AuthenticationElementsAuthWrapper struct {
	AuthenticationElements
	auth Authentication
}

func NewAuthenticationElementsAuthWrapper(elements AuthenticationElements, auth Authentication) *AuthenticationElementsAuthWrapper {
	ret := &AuthenticationElementsAuthWrapper{}
	ret.AuthenticationElements = elements
	ret.auth = auth
	return ret
}

func (w *AuthenticationElementsAuthWrapper) GetAuthentication() Authentication {
	return w.auth
}
