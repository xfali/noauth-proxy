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

package test

import (
	"bytes"
	"fmt"
	"github.com/xfali/noauth-proxy/pkg/auth"
	"io"
	"log"
	"net/http"
	url2 "net/url"
	"testing"
)

func TestToken(t *testing.T) {
	data := auth.UsernamePasswordAuthentication{
		Host:     "127.0.0.1",
		Port:     8081,
		Protocol: "http",
		Username: "test",
		Password: "test",
	}
	data.SetEncrypt(nil)
	d, _ := data.AuthMarshal()
	resp, err := http.Post("http://localhost:8080/_token?auth_type=test", "application/json", bytes.NewReader(d))
	if err != nil {
		log.Fatal(err)
	}
	log.Print(resp.Status)
	buf := &bytes.Buffer{}
	io.Copy(buf, resp.Body)
	resp.Body.Close()

	token := buf.String()
	t.Log(token)

	url := url2.QueryEscape("http://localhost:8080/test")
	target := fmt.Sprintf("http://localhost:8080/_redirect?auth_type=test&token=%s&redirect=%s", token, url)
	log.Print(target)
	//request, _ := http.NewRequest(http.MethodGet,
	//	target,
	//	nil)
	////authData = authData
	//resp, err = http.DefaultClient.Do(request)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Print(resp.Status)
	//io.Copy(os.Stdout, resp.Body)
	//resp.Body.Close()
}
