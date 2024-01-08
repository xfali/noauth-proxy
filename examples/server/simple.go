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
	"fmt"
	ex_auth "github.com/xfali/noauth-proxy/examples/auth"
	"github.com/xfali/noauth-proxy/pkg/app"
	"github.com/xfali/noauth-proxy/pkg/auth"
	"github.com/xfali/noauth-proxy/pkg/server"
	"os"
)

func main() {
	log := func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(os.Stderr, format, args...)
	}
	h := server.NewHandler(log)
	defer h.Close()
	auth.Register("test", auth.NewAuthenticator(&ex_auth.ExampleAuthentication{}))
	go func() {
		ex_auth.Run(8081)
	}()
	app.RunWithServerOpts(log,
		server.OptAddHandle("/", h.Proxy),
		server.OptAddHandle("/_switch", h.Switch),
		server.OptAddHandle("/_token", h.GenerateToken),
		server.OptAddHandle("/_redirect", h.Redirect),
	)
}
