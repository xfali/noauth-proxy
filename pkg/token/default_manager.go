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
	"fmt"
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

type Keyable interface {
	Key() string
}

type Filter interface {
	Filter(k Keyable) (Token, bool)
	Update(k Keyable, token Token)
	Remove(k Keyable)
}

type defaultManager struct {
	policy    RevocationPolicy
	tokens    map[Token]*tokenData
	tokenLock sync.RWMutex

	filter         Filter
	maxRetryTimes  int
	tokenGenerator TokenGenerator
	purgeInterval  time.Duration
	stopCh         chan struct{}
}

type defaultManagerOpt func(*defaultManager)
type TokenGenerator func(data interface{}) Token

func defaultTokenGenerator(data interface{}) Token {
	return FromString(RandomToken(32))
}

func NewManager(opts ...defaultManagerOpt) *defaultManager {
	ret := &defaultManager{
		tokens:         map[Token]*tokenData{},
		stopCh:         make(chan struct{}),
		tokenGenerator: defaultTokenGenerator,
		maxRetryTimes:  3,
		purgeInterval:  0,
	}
	for _, opt := range opts {
		opt(ret)
	}
	if ret.purgeInterval > 0 {
		go ret.purgeLoop(ret.purgeInterval)
	}
	return ret
}

func (m *defaultManager) SetRevocationPolicy(policy RevocationPolicy) {
	m.policy = policy
}

func (m *defaultManager) Generate(ctx context.Context, data interface{}, expire time.Time) (Token, error) {
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	keyable := false
	if m.filter != nil {
		if k, ok := data.(Keyable); ok {
			keyable = true
			if t, have := m.filter.Filter(k); have {
				if _, hh := m.tokens[t]; !hh {
					m.filter.Remove(k)
				} else {
					return t, nil
				}
			}
		}
	}

	for i := 0; i < m.maxRetryTimes; i++ {
		token := m.tokenGenerator(data)
		if _, ok := m.tokens[token]; !ok {
			if s, ok := data.(Setter); ok {
				s.Set(token)
			}
			m.tokens[token] = &tokenData{
				expireTime: expire,
				data:       data,
			}
			if m.filter != nil {
				if keyable {
					m.filter.Update(data.(Keyable), token)
				}
			}
			return Token(token), nil
		}
	}
	return "", fmt.Errorf("Cannot generate token in %d times ", m.maxRetryTimes)
}

func (m *defaultManager) Set(ctx context.Context, token Token, data interface{}, expire time.Time, flag SetFlag) error {
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	_, have := m.tokens[token]
	if have {
		if flag&SetFlagNotExist != 0 {
			return fmt.Errorf("Flag is SetFlagNotExist but value found ")
		}
	} else {
		if flag&SetFlagMustExist != 0 {
			return fmt.Errorf("Flag is SetFlagMustExist but value not found ")
		}
	}

	if s, ok := data.(Setter); ok {
		s.Set(token)
	}
	m.tokens[token] = &tokenData{
		expireTime: expire,
		data:       data,
	}
	return nil
}

func (m *defaultManager) Get(ctx context.Context, token Token) (interface{}, error) {
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	if v, ok := m.tokens[token]; ok {
		if !v.expireTime.IsZero() {
			now := clock.Now()
			if m.processExpire(now, token, v) {
				return nil, errors.New("Invalid Token ")
			}
		}

		if m.policy != nil && m.policy.OnTouch(token) {
			delete(m.tokens, token)
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

func (m *defaultManager) processExpire(now time.Time, token Token, data *tokenData) bool {
	if data.expireTime.IsZero() {
		return false
	}
	if data.expireTime.Before(now) {
		if m.policy != nil && !m.policy.OnExpire(token) {
			return true
		}
		delete(m.tokens, token)
		return true
	}
	return false
}

func (m *defaultManager) doPurge() {
	now := clock.Now()
	m.tokenLock.Lock()
	defer m.tokenLock.Unlock()

	for k, v := range m.tokens {
		_ = m.processExpire(now, Token(k), v)
	}
}

type managerOpts struct {
}

var ManagerOpts managerOpts

func (o managerOpts) PurgeInterval(t time.Duration) defaultManagerOpt {
	return func(manager *defaultManager) {
		manager.purgeInterval = t
	}
}

func (o managerOpts) TokenGenerator(generator TokenGenerator) defaultManagerOpt {
	return func(manager *defaultManager) {
		manager.tokenGenerator = generator
	}
}

func (o managerOpts) GenerateTokenMaxRetryTime(t int) defaultManagerOpt {
	return func(manager *defaultManager) {
		manager.maxRetryTimes = t
	}
}

func (o managerOpts) Filter(filter Filter) defaultManagerOpt {
	return func(manager *defaultManager) {
		manager.filter = filter
	}
}

func (o managerOpts) RevocationPolicy(policy RevocationPolicy) defaultManagerOpt {
	return func(manager *defaultManager) {
		manager.policy = policy
	}
}

type DummyFilter struct {
}

func (f DummyFilter) Filter(k Keyable) (Token, bool) {
	return "", false
}

func (f DummyFilter) Update(k Keyable, token Token) {

}

func (f DummyFilter) Remove(k Keyable) {

}

type MapFilter struct {
	data map[string]Token
}

func NewMapFilter() *MapFilter {
	return &MapFilter{
		data: map[string]Token{},
	}
}

func (f *MapFilter) Filter(k Keyable) (Token, bool) {
	v, ok := f.data[k.Key()]
	return v, ok
}

func (f *MapFilter) Update(k Keyable, token Token) {
	f.data[k.Key()] = token
}

func (f *MapFilter) Remove(k Keyable) {
	delete(f.data, k.Key())
}
