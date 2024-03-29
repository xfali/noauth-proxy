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
	"time"
)

type SetFlag int

const (
	SetFlagNone      = 0
	SetFlagNotExist  = 1
	SetFlagMustExist = 1 << 1
)

type Manager interface {
	SetRevocationPolicy(policy RevocationPolicy)
	Generate(ctx context.Context, data interface{}, expire time.Time) (Token, error)
	Set(ctx context.Context, token Token, data interface{}, expire time.Time, flag SetFlag) error
	Close() error
	Get(ctx context.Context, token Token) (interface{}, error)
}
