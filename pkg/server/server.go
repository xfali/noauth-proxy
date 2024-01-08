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
	"fmt"
	"net/http"
)

var (
	DefaultPort = 8080
)

type server struct {
	svr  *http.Server
	host string
	port int
	key  string
	crt  string
}
type Opt func(*server)

func NewServer(opts ...Opt) *server {
	srv := &server{}
	for _, opt := range opts {
		opt(srv)
	}

	srv.init()
	return srv
}

func OptHttp(host string, port int) Opt {
	return func(s *server) {
		s.host = host
		s.port = port
	}
}

func OptTlsFile(cert, key string) Opt {
	return func(s *server) {
		s.crt = cert
		s.key = key
	}
}

func (s *server) init() {
	if s.port == 0 {
		s.port = DefaultPort
	}
	s.svr = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.host, s.port),
		Handler: http.DefaultServeMux,
	}
}

func (s *server) Start() error {
	if s.crt != "" {
		return s.svr.ListenAndServeTLS(s.crt, s.key)
	}
	return s.svr.ListenAndServe()
}

func (s *server) Close() error {
	if s.svr != nil {
		return s.svr.Close()
	}
	return nil
}
