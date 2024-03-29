/*
 *
 * Copyright 2023 puzzleloginserver authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	_ "embed"

	dbclient "github.com/dvaumoron/puzzledbclient"
	grpcserver "github.com/dvaumoron/puzzlegrpcserver"
	"github.com/dvaumoron/puzzleloginserver/loginserver"
	pb "github.com/dvaumoron/puzzleloginservice"
)

//go:embed version.txt
var version string

func main() {
	s := grpcserver.Make(loginserver.LoginKey, version)
	pb.RegisterLoginServer(s, loginserver.New(dbclient.Create(s.Logger), s.Logger))
	s.Start()
}
