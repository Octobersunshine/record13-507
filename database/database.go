package database

import (
	"privilege-vault/config"
	"privilege-vault/models"
	"privilege-vault/utils"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(sqlite.Open(config.AppConfig.DatabasePath), &gorm.Config{})
	if err != nil {
		return err
	}

	err = DB.AutoMigrate(
		&models.User{},
		&models.PrivilegeAccount{},
		&models.OperationRequest{},
		&models.AuditLog{},
		&models.OperationSession{},
		&models.SessionCommandRecord{},
	)
	if err != nil {
		return err
	}

	return seedInitialData()
}

func seedInitialData() error {
	var count int64
	DB.Model(&models.User{}).Count(&count)
	if count > 0 {
		return nil
	}

	defaultPassword := "admin123"
	hashedPass, err := utils.HashPassword(defaultPassword)
	if err != nil {
		return err
	}

	admin := &models.User{
		Username: "admin",
		Password: hashedPass,
		Role:     "super_admin",
		RealName: "超级管理员",
		Email:    "admin@example.com",
		Phone:    "13800138000",
		Status:   1,
	}
	if err := DB.Create(admin).Error; err != nil {
		return err
	}

	opsUser := &models.User{
		Username: "ops001",
		Password: hashedPass,
		Role:     "operator",
		RealName: "运维工程师001",
		Email:    "ops001@example.com",
		Phone:    "13800138001",
		Status:   1,
	}
	if err := DB.Create(opsUser).Error; err != nil {
		return err
	}

	reviewer := &models.User{
		Username: "reviewer01",
		Password: hashedPass,
		Role:     "reviewer",
		RealName: "审批人01",
		Email:    "reviewer01@example.com",
		Phone:    "13800138002",
		Status:   1,
	}
	if err := DB.Create(reviewer).Error; err != nil {
		return err
	}

	return nil
}
