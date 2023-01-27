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
package loginserver

import (
	"context"
	"errors"
	"strings"

	"github.com/dvaumoron/puzzleloginserver/model"
	pb "github.com/dvaumoron/puzzleloginservice"
	"gorm.io/gorm"
)

type empty = struct{}

// server is used to implement puzzleloginservice.LoginServer.
type server struct {
	pb.UnimplementedLoginServer
	db *gorm.DB
}

func New(db *gorm.DB) pb.LoginServer {
	return server{db: db}
}

func (s server) Verify(ctx context.Context, request *pb.LoginRequest) (*pb.Response, error) {
	var user model.User
	err := s.db.First(&user, "login = ?", request.Login).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}
		return nil, err
	}

	if request.Salted != user.Password {
		return &pb.Response{}, nil
	}
	return &pb.Response{Success: true, Id: user.ID}, nil
}

func (s server) Register(ctx context.Context, request *pb.LoginRequest) (*pb.Response, error) {
	var user model.User
	err := s.db.First(&user, "login = ?", request.Login).Error
	if err == nil {
		// login already used, return false (bool default)
		return &pb.Response{}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		// some technical error, send it
		return nil, err
	}

	// unknown user, create new
	user = model.User{Login: request.Login, Password: request.Salted}
	if err = s.db.Create(&user).Error; err != nil {
		return nil, err
	}
	return &pb.Response{Success: true, Id: user.ID}, nil
}

func (s server) ChangeLogin(ctx context.Context, request *pb.ChangeLoginRequest) (*pb.Response, error) {
	var user model.User
	err := s.db.First(&user, "id = ?", request.UserId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}
		return nil, err
	}

	if request.Salted != user.Password {
		return &pb.Response{}, nil
	}
	if err = s.db.Model(&user).Update("login", request.NewLogin).Error; err != nil {
		return nil, err
	}
	return &pb.Response{Success: true}, nil
}

func (s server) ChangePassword(ctx context.Context, request *pb.ChangePasswordRequest) (*pb.Response, error) {
	var user model.User
	err := s.db.First(&user, "id = ?", request.UserId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}
		return nil, err
	}

	if request.OldSalted != user.Password {
		return &pb.Response{}, nil
	}
	if err = s.db.Model(&user).Update("password", request.NewSalted).Error; err != nil {
		return nil, err
	}
	return &pb.Response{Success: true}, nil
}

func (s server) GetUsers(ctx context.Context, request *pb.UserIds) (*pb.Users, error) {
	var users []model.User
	err := s.db.Find(&users, "id IN ?", request.Ids).Error
	if err != nil {
		return nil, err
	}
	return &pb.Users{List: convertUsersFromModel(users)}, nil
}

func (s server) ListUsers(ctx context.Context, request *pb.RangeRequest) (*pb.Users, error) {
	var total int64
	err := s.db.Model(&model.User{}).Count(&total).Error
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return &pb.Users{}, nil
	}

	var users []model.User
	page := s.paginate(request.Start, request.End)
	if filter := request.Filter; filter == "" {
		err = page.Find(&users).Error
	} else {
		var likeBuilder strings.Builder
		likeBuilder.WriteByte('%')
		likeBuilder.WriteString(filter)
		likeBuilder.WriteByte('%')
		err = page.Find(&users, "login LIKE ?", likeBuilder.String()).Error
	}

	if err != nil {
		return nil, err
	}
	return &pb.Users{List: convertUsersFromModel(users), Total: uint64(total)}, nil
}

func (s server) Delete(ctx context.Context, request *pb.UserId) (*pb.Response, error) {
	err := s.db.Delete(&model.User{}, request.Id).Error
	if err != nil {
		return nil, err
	}
	return &pb.Response{Success: true}, nil
}

func (s server) paginate(start uint64, end uint64) *gorm.DB {
	return s.db.Offset(int(start)).Limit(int(end - start))
}

func convertUsersFromModel(users []model.User) []*pb.User {
	resUsers := make([]*pb.User, 0, len(users))
	for _, user := range users {
		resUsers = append(resUsers, &pb.User{
			Id: user.ID, Login: user.Login, RegistredAt: user.CreatedAt.Unix(),
		})
	}
	return resUsers
}
