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
	"encoding/json"
	"github.com/xfali/noauth-proxy/pkg/encrypt"
	token2 "github.com/xfali/noauth-proxy/pkg/token"
	"net/http"
)

var (
	token = token2.RandomToken(16)
)

type ExampleAuthenticationElement struct {
	AuthKey string `json:"key"`
}

func (a *ExampleAuthenticationElement) AuthMarshal() ([]byte, error) {
	return json.Marshal(a)
}

func (a *ExampleAuthenticationElement) AuthUnmarshal(data []byte) error {
	return json.Unmarshal(data, a)
}

func (a *ExampleAuthenticationElement) Key() string {
	return a.AuthKey
}

func (a *ExampleAuthenticationElement) AttachToRequest(req *http.Request) {
	req.Header.Add("Authorization", token)
}

func Refresh(ctx context.Context) error {
	token = token2.RandomToken(16)
	return nil
}

func (a *ExampleAuthenticationElement) SetEncrypt(service encrypt.Service) {

}
