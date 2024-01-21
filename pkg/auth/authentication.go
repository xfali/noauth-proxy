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

type Marshaler interface {
	AuthMarshal() ([]byte, error)
}

type Unmarshaler interface {
	AuthUnmarshal([]byte) error
}

type Authentication interface {
	Key() string
	SetEncrypt(service encrypt.Service)
	PassAddress() string
}

type RequestAttacher interface {
	AttachToRequest(req *http.Request)
}

type ResponseAttacher interface {
	AttachToResponse(resp http.ResponseWriter)
}

type AuthenticationElements interface {
	Key() string
	SetEncrypt(service encrypt.Service)
	RequestAttacher
}

type AuthenticationRefresher interface {
	Refresh(ctx context.Context, auth AuthenticationElements) error
	CreateAuthenticationElements(ctx context.Context, auth Authentication) (AuthenticationElements, error)
}
