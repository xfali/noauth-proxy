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
	"crypto/rand"
	"encoding/base64"
	"github.com/xfali/noauth-proxy/pkg/auth"
	"net/http"
)

var (
	token = randomToken(16)
)

type ExampleAuthentication struct {
	auth.UsernamePasswordAuthentication
}

func (a *ExampleAuthentication) AttachToRequest(req *http.Request) {
	req.Header.Add("Authorization", token)
}

func (a *ExampleAuthentication) Refresh(ctx context.Context) error {
	token = randomToken(16)
	return nil
}

func randomToken(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "ERROR"
	}
	return base64.URLEncoding.EncodeToString(b)
}
