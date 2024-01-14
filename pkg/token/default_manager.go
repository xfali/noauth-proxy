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

package token

import (
	"context"
	"errors"
	"github.com/xfali/noauth-proxy/pkg/clock"
	"sync"
	"time"
)

const (
	defaultPurgeInterval = 60 * time.Second
)

type tokenData struct {
	data       interface{}
	expireTime time.Time
}

type defaultManager struct {
	policy    RevocationPolicy
	tokens    map[string]*tokenData
	tokenLock sync.RWMutex
	stopCh    chan struct{}
}

func NewManager(purgeInterval time.Duration) *defaultManager {
	ret := &defaultManager{
		tokens: map[string]*tokenData{},
		stopCh: make(chan struct{}),
	}
	if purgeInterval <= 0 {
		purgeInterval = defaultPurgeInterval
	}
	go ret.purgeLoop(purgeInterval)
	return ret
}

func (m *defaultManager) SetRevocationPolicy(policy RevocationPolicy) {
	m.policy = policy
}

func (m *defaultManager) Generate(ctx context.Context, data interface{}, expire time.Time) (Token, error) {
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	for {
		token := RandomToken(32)
		if _, ok := m.tokens[token]; !ok {
			m.tokens[token] = &tokenData{
				expireTime: expire,
				data:       data,
			}
			return Token(token), nil
		}
	}
}

func (m *defaultManager) Get(ctx context.Context, token Token) (interface{}, error) {
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	t := string(token)
	if v, ok := m.tokens[t]; ok {
		if m.policy != nil && m.policy.OnTouch(token) {
			delete(m.tokens, t)
		}
		return v.data, nil
	}
	return nil, errors.New("Invalid Token ")
}

func (m *defaultManager) Close() error {
	select {
	case <-m.stopCh:
		return nil
	default:
		close(m.stopCh)
		m.tokens = nil
	}
	return nil
}

func (m *defaultManager) purgeLoop(purgeInterval time.Duration) {
	ticker := time.NewTicker(purgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.doPurge()
		}
	}
}

func (m *defaultManager) doPurge() {
	now := clock.Now()
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	for k, v := range m.tokens {
		if v.expireTime.Before(now) {
			if m.policy != nil && !m.policy.OnExpire(Token(k)) {
				continue
			}
			delete(m.tokens, k)
		}
	}
}
