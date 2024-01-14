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

package errs

import "fmt"

type ErrorList []error

func (e *ErrorList) Add(err error) *ErrorList {
	*e = append(*e, err)
	return e
}

func (e ErrorList) Empty() bool {
	return len(e) == 0
}

func (e ErrorList) Error() string {
	switch len(e) {
	case 0:
		return "no errors"
	case 1:
		return e[0].Error()
	}
	return fmt.Sprintf("%s (and %d more errors)", e[0], len(e)-1)
}
