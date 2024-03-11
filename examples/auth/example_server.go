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
	"fmt"
	"log"
	"net/http"
)

func Run(port int) error {
	mux := &http.ServeMux{}
	first := true
	mux.HandleFunc("/test", func(writer http.ResponseWriter, request *http.Request) {
		if first {
			first = false
			log.Println("First")
			http.Error(writer, "No Authorization: first 401", http.StatusUnauthorized)
			return
		}
		v := request.Header.Get("Authorization")
		log.Printf("token: %s expect: %s\n", v, token)
		tokenLocker.Lock()
		defer tokenLocker.Unlock()
		if v == "" || v != token {
			http.Error(writer, "No Authorization: invalid token", http.StatusUnauthorized)
			return
		}
		writer.Write([]byte("Hello world"))
	})
	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	return srv.ListenAndServe()
}
