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

	dbclient "github.com/dvaumoron/puzzledbclient"
	"github.com/dvaumoron/puzzleloginserver/model"
	pb "github.com/dvaumoron/puzzleloginservice"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const LoginKey = "puzzleLogin"

const dbAccessMsg = "Failed to access database"

var errInternal = errors.New("internal service error")

// server is used to implement puzzleloginservice.LoginServer.
type server struct {
	pb.UnimplementedLoginServer
	db     *gorm.DB
	logger *otelzap.Logger
}

func New(db *gorm.DB, logger *otelzap.Logger) pb.LoginServer {
	db.AutoMigrate(&model.User{})
	return server{db: db, logger: logger}
}

func (s server) Verify(ctx context.Context, request *pb.LoginRequest) (*pb.Response, error) {
	logger := s.logger.Ctx(ctx)
	var user model.User
	err := s.db.First(&user, "login = ?", request.Login).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}

		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}

	if request.Salted != user.Password {
		return &pb.Response{}, nil
	}
	return &pb.Response{Success: true, Id: user.ID}, nil
}

func (s server) Register(ctx context.Context, request *pb.LoginRequest) (*pb.Response, error) {
	logger := s.logger.Ctx(ctx)
	login := request.Login
	if login == "" {
		return &pb.Response{}, nil
	}

	var user model.User
	err := s.db.First(&user, "login = ?", login).Error
	if err == nil {
		// login already used, return false (bool default)
		return &pb.Response{}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		// some technical error, send it
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}

	// unknown user, create new
	user = model.User{Login: login, Password: request.Salted}
	if err = s.db.Create(&user).Error; err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Response{Success: true, Id: user.ID}, nil
}

func (s server) ChangeLogin(ctx context.Context, request *pb.ChangeRequest) (*pb.Response, error) {
	logger := s.logger.Ctx(ctx)
	newLogin := request.NewLogin
	if newLogin == "" {
		return &pb.Response{}, nil
	}

	var user model.User
	err := s.db.First(&user, "id = ?", request.UserId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}

		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}

	if request.OldSalted != user.Password {
		return &pb.Response{}, nil
	}

	err = s.db.First(&user, "login = ?", newLogin).Error
	if err == nil {
		// login already used
		return &pb.Response{}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}

	err = s.db.Model(&user).Updates(map[string]any{
		"login": newLogin, "password": request.NewSalted,
	}).Error
	if err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Response{Success: true}, nil
}

func (s server) ChangePassword(ctx context.Context, request *pb.ChangeRequest) (*pb.Response, error) {
	logger := s.logger.Ctx(ctx)
	var user model.User
	err := s.db.First(&user, "id = ?", request.UserId).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// unknown user, return false (bool default)
			return &pb.Response{}, nil
		}

		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}

	if request.OldSalted != user.Password {
		return &pb.Response{}, nil
	}
	if err = s.db.Model(&user).Update("password", request.NewSalted).Error; err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Response{Success: true}, nil
}

func (s server) GetUsers(ctx context.Context, request *pb.UserIds) (*pb.Users, error) {
	logger := s.logger.Ctx(ctx)
	var users []model.User
	if err := s.db.Find(&users, "id IN ?", request.Ids).Error; err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Users{List: convertUsersFromModel(users)}, nil
}

func (s server) ListUsers(ctx context.Context, request *pb.RangeRequest) (*pb.Users, error) {
	logger := s.logger.Ctx(ctx)
	filter := request.Filter
	noFilter := filter == ""

	userRequest := s.db.Model(&model.User{})
	if !noFilter {
		filter = dbclient.BuildLikeFilter(filter)
		userRequest.Where("login LIKE ?", filter)
	}
	var total int64
	err := userRequest.Count(&total).Error
	if err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	if total == 0 {
		return &pb.Users{}, nil
	}

	var users []model.User
	page := dbclient.Paginate(s.db, request.Start, request.End).Order("login asc")
	if noFilter {
		err = page.Find(&users).Error
	} else {
		err = page.Find(&users, "login LIKE ?", filter).Error
	}

	if err != nil {
		logger.Error(dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Users{List: convertUsersFromModel(users), Total: uint64(total)}, nil
}

func (s server) Delete(ctx context.Context, request *pb.UserId) (*pb.Response, error) {
	if err := s.db.Delete(&model.User{}, request.Id).Error; err != nil {
		s.logger.ErrorContext(ctx, dbAccessMsg, zap.Error(err))
		return nil, errInternal
	}
	return &pb.Response{Success: true}, nil
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
