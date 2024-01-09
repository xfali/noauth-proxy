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
	DefaultPort     = 8080
	PatternProxy    = "/"
	PatternPrepare  = "/_prepare"
	PatternToken    = "/_token"
	PatternRedirect = "/_redirect"
)

type server struct {
	srv  *http.Server
	mux  *http.ServeMux
	host string
	port int
	key  string
	crt  string
}
type Opt func(*server)

func NewServer(opts ...Opt) *server {
	srv := &server{
		mux: &http.ServeMux{},
	}
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

func OptAddHandle(pattern string, handlerFunc http.HandlerFunc) Opt {
	return func(s *server) {
		s.mux.HandleFunc(pattern, handlerFunc)
	}
}

func OptRegister(registers ...HttpHandlerRegister) Opt {
	return func(s *server) {
		for _, r := range registers {
			r.RegisterHandler(s.mux.HandleFunc)
		}
	}
}

func OptAutoHandle(o interface{}) Opt {
	return func(s *server) {
		if v, ok := o.(ProxyHandler); ok {
			s.mux.HandleFunc(PatternProxy, v.Proxy)
			s.mux.HandleFunc(PatternPrepare, v.Prepare)
		}
		if v, ok := o.(TokenHandler); ok {
			s.mux.HandleFunc(PatternToken, v.GenerateToken)
			s.mux.HandleFunc(PatternRedirect, v.Redirect)
		}
	}
}

func (s *server) init() {
	if s.port == 0 {
		s.port = DefaultPort
	}
	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.host, s.port),
		Handler: s.mux,
	}
}

func (s *server) Start() error {
	if s.crt != "" {
		return s.srv.ListenAndServeTLS(s.crt, s.key)
	}
	return s.srv.ListenAndServe()
}

func (s *server) Close() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}
