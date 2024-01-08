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
	"github.com/xfali/noauth-proxy/pkg/auth"
	"github.com/xfali/noauth-proxy/pkg/log"
	"github.com/xfali/noauth-proxy/pkg/token"
	"time"
)

type tokenHandler struct {
	logger          log.LogFunc
	tokenMgr        token.Manager
	authMgr         auth.AuthenticatorManager
	tokenExpireTime time.Duration
}

func NewTokenHandler(logger log.LogFunc) *tokenHandler {
	t := token.NewManager(-1)
	ret := &tokenHandler{
		logger:   logger,
		tokenMgr: t,
		authMgr:  auth.DefaultAuthenticatorMgr,
	}
	return ret
}

func (h *tokenHandler) RegisterHandler(f RegisterFunc) {
	f("/_token", h.GenerateToken)
	f("/redirect", h.Redirect)
}
