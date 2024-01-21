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
	"github.com/xfali/noauth-proxy/pkg/encrypt"
	"net/http"
)

type Authenticator interface {
	SetEncrypt(service encrypt.Service)
	ReadAuthentication(ctx context.Context, req *http.Request) (Authentication, error)
	AttachAuthenticationElement(ctx context.Context, resp http.ResponseWriter, auth Authentication) error
	ExtractAuthenticationElement(ctx context.Context, req *http.Request) (AuthenticationElements, error)
	Close() error
	AuthenticationRefresher
}

type AttachAuthenticationElementNotifier interface {
	AuthenticationElementAttached(ctx context.Context, resp http.ResponseWriter, authentication Authentication, authenticationElements AuthenticationElements) error
}
