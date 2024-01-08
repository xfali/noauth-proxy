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

package app

import (
	"github.com/xfali/noauth-proxy/pkg/log"
	"github.com/xfali/noauth-proxy/pkg/server"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type RunArgs struct {
	Host     string
	Port     int
	CertFile string
	KeyFile  string
}

func Run(logger log.LogFunc, args *RunArgs) {
	if args == nil {
		args = &RunArgs{}
	}
	svr := server.NewServer(server.OptHttp(args.Host, args.Port), server.OptTlsFile(args.CertFile, args.KeyFile))
	go func() {
		err := svr.Start()
		if err != nil {
			logger("Start server with args %v failed, exit", err)
			os.Exit(1)
		}
	}()
	wait(logger, svr)
}

func RunWithServerOpts(logger log.LogFunc, opts ...server.Opt) {
	svr := server.NewServer(opts...)
	go func() {
		err := svr.Start()
		if err != nil {
			logger("Start server with args %v failed, exit", err)
			os.Exit(1)
		}
	}()
	wait(logger, svr)
}

func wait(logger log.LogFunc, closers ...io.Closer) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	for {
		si := <-ch
		switch si {
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
			time.Sleep(100 * time.Millisecond)
			for _, c := range closers {
				err := c.Close()
				if err != nil {
					logger("Close error: %v\n", err)
				}
			}
			time.Sleep(1 * time.Second)
			logger("Process exited")
			return
		case syscall.SIGHUP:
		default:
			return
		}
	}
}
