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
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	dbclient "github.com/dvaumoron/puzzledbclient"
	"github.com/dvaumoron/puzzleloginserver/model"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

const dbErrorMsg = "Database error :"

func salt(password string) string {
	// TODO improve the security
	sha512Hasher := sha512.New()
	sha512Hasher.Write([]byte(password))
	return hex.EncodeToString(sha512Hasher.Sum(nil))
}

func main() {
	if len(os.Args) < 4 {
		log.Fatal("Wait id, login, password for the initial admin user as argument")
	}

	adminUserIdStr := os.Args[1]
	adminUserId, err := strconv.ParseUint(adminUserIdStr, 10, 64)
	if err != nil {
		log.Fatal("Failed to parse the id as an integer")
	}

	adminUserLogin := os.Args[2]
	adminUserPassword := salt(os.Args[3])

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load .env file")
	}

	db := dbclient.Create()

	db.AutoMigrate(&model.User{})

	var user model.User
	err = db.First(&user, adminUserId).Error
	if err == nil {
		// the user already exist, nothing to do
		return
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Fatal(dbErrorMsg, err)
	}

	user = model.User{
		ID: adminUserId, CreatedAt: time.Now(), Login: adminUserLogin, Password: adminUserPassword,
	}
	if err = db.Save(&user).Error; err != nil {
		log.Fatal(dbErrorMsg, err)
	}
}
