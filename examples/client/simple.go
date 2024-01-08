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

package main

import (
	"bytes"
	"github.com/xfali/noauth-proxy/pkg/auth"
	"github.com/xfali/noauth-proxy/pkg/server"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	data := auth.UsernamePasswordAuthentication{
		Host:     "127.0.0.1",
		Port:     8081,
		Protocol: "http",
		Username: "test",
		Password: "test",
	}
	data.SetEncrypt(nil)
	d, _ := data.AuthMarshal()
	resp, err := http.Post("http://localhost:8080/_switch?auth_type=test", "application/json", bytes.NewReader(d))
	if err != nil {
		log.Fatal(err)
	}
	log.Print(resp.Status)
	resp.Body.Close()
	var (
		authType *http.Cookie
		authData *http.Cookie
	)
	cookies := resp.Cookies()
	for _, c := range cookies {
		log.Print(c)
		if c.Name == server.CookieNameType {
			authType = c
		} else if c.Name == auth.CookieNamePayload {
			authData = c
		}
	}
	request, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/test", nil)
	request.AddCookie(authType)
	request.AddCookie(authData)
	//authData = authData
	resp, err = http.DefaultClient.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(resp.Status)
	io.Copy(os.Stdout, resp.Body)
	resp.Body.Close()
}
