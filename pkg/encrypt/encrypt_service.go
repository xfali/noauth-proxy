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

package encrypt

type Service interface {
	Encrypt(originData []byte) ([]byte, error)
	Decrypt(encryptData []byte) ([]byte, error)
}

const (
	defaultKey = "&FjaGsf89@*HFEofuijawf89j@_(I5_1"
)

var (
	globalService = NewService()
)

type defaultService struct {
	key []byte
}

func NewService() *defaultService {
	return NewServiceWithKey([]byte(defaultKey))
}

func NewServiceWithKey(key []byte) *defaultService {
	return &defaultService{
		key: key,
	}
}

func (s *defaultService) Encrypt(originData []byte) ([]byte, error) {
	return AesEncrypt(originData, s.key)
}

func (s *defaultService) Decrypt(encryptData []byte) ([]byte, error) {
	return AesDecrypt(encryptData, s.key)
}

func Encrypt(originData []byte) ([]byte, error) {
	return globalService.Encrypt(originData)
}

func Decrypt(encryptData []byte) ([]byte, error) {
	return globalService.Decrypt(encryptData)
}

func GlobalService() Service {
	return globalService
}
