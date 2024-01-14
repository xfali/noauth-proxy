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
	"bytes"
	"net/http"
)

type ResponseWriterWrapper interface {
	http.ResponseWriter

	Reset(w http.ResponseWriter)
	DoFlush() error
	HttpStatus() int
}

type responseWriter struct {
	http.ResponseWriter
	buf  bytes.Buffer
	code int
}

func DefaultResponseWriter() ResponseWriterWrapper {
	return newResponseWriter()
}

func newResponseWriter() *responseWriter {
	ret := responseWriter{}
	ret.code = DefaultHttpStatus
	return &ret
}

func (r *responseWriter) HttpStatus() int {
	return r.code
}

func (r *responseWriter) WriteHeader(statusCode int) {
	r.code = statusCode
	//r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseWriter) Write(d []byte) (int, error) {
	return r.buf.Write(d)
}

func (r *responseWriter) WriteString(d string) (int, error) {
	return r.buf.WriteString(d)
}

func (r *responseWriter) Reset(w http.ResponseWriter) {
	r.buf.Reset()
	r.ResponseWriter = w
	r.code = DefaultHttpStatus
}

func (r *responseWriter) DoFlush() error {
	r.ResponseWriter.WriteHeader(r.code)
	_, err := r.ResponseWriter.Write(r.buf.Bytes())
	return err
}
