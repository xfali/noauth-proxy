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
	"github.com/xfali/noauth-proxy/pkg/errs"
	"sync"
)

var DefaultAuthenticatorMgr = NewAuthenticatorMgr()

type defaultAuthenticatorMgr struct {
	authenticators map[string]Authenticator
	authLock       sync.RWMutex
}

func NewAuthenticatorMgr() *defaultAuthenticatorMgr {
	return &defaultAuthenticatorMgr{
		authenticators: map[string]Authenticator{},
	}
}

func (m *defaultAuthenticatorMgr) Register(authType string, authenticator Authenticator) bool {
	m.authLock.Lock()
	defer m.authLock.Unlock()

	_, ok := m.authenticators[authType]
	m.authenticators[authType] = authenticator
	return ok
}

func (m *defaultAuthenticatorMgr) GetAuthenticator(ctx context.Context, authType string) (authenticator Authenticator, have bool) {
	m.authLock.RLock()
	defer m.authLock.RUnlock()

	v, ok := m.authenticators[authType]
	return v, ok
}

func (m *defaultAuthenticatorMgr) Close() error {
	m.authLock.RLock()
	defer m.authLock.RUnlock()

	var errList errs.ErrorList
	for _, v := range m.authenticators {
		err := v.Close()
		if err != nil {
			_ = errList.Add(err)
		}
	}
	if errList.Empty() {
		return nil
	}
	return errList
}

func Register(authType string, authenticator Authenticator) bool {
	return DefaultAuthenticatorMgr.Register(authType, authenticator)
}

func GetAuthenticator(ctx context.Context, authType string) (authenticator Authenticator, have bool) {
	return DefaultAuthenticatorMgr.GetAuthenticator(ctx, authType)
}
