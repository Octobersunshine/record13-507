package controllers

import (
	"encoding/json"
	"net/http"
	"privilege-vault/config"
	"privilege-vault/database"
	"privilege-vault/models"
	"privilege-vault/utils"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type CreateAccountRequest struct {
	AccountName    string `json:"account_name" binding:"required"`
	SystemName     string `json:"system_name" binding:"required"`
	SystemType     string `json:"system_type" binding:"required,oneof=linux windows database middleware network other"`
	Host           string `json:"host" binding:"required"`
	Port           int    `json:"port"`
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	Description    string `json:"description"`
	AllowedUserIDs []uint `json:"allowed_user_ids"`
	NeedReview     *bool  `json:"need_review"`
}

type UpdateAccountRequest struct {
	AccountName    string `json:"account_name"`
	SystemName     string `json:"system_name"`
	SystemType     string `json:"system_type"`
	Host           string `json:"host"`
	Port           *int   `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Description    string `json:"description"`
	AllowedUserIDs []uint `json:"allowed_user_ids"`
	NeedReview     *bool  `json:"need_review"`
	Status         *int   `json:"status"`
}

func ListPrivilegeAccounts(c *gin.Context) {
	var accounts []models.PrivilegeAccount
	query := database.DB.Preload("Owner")

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	if role.(string) == "operator" {
		query = query.Joins("LEFT JOIN users ON users.id = privilege_accounts.owner_id").
			Where("privilege_accounts.owner_id = ? OR privilege_accounts.status = 1", userID.(uint))
	}

	systemType := c.Query("system_type")
	if systemType != "" {
		query = query.Where("system_type = ?", systemType)
	}

	keyword := c.Query("keyword")
	if keyword != "" {
		query = query.Where("account_name LIKE ? OR system_name LIKE ? OR host LIKE ?",
			"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%")
	}

	query.Find(&accounts)

	result := make([]gin.H, 0)
	for _, acc := range accounts {
		var allowedIDs []uint
		if acc.AllowedUserIDs != "" {
			json.Unmarshal([]byte(acc.AllowedUserIDs), &allowedIDs)
		}
		result = append(result, gin.H{
			"id":               acc.ID,
			"account_name":     acc.AccountName,
			"system_name":      acc.SystemName,
			"system_type":      acc.SystemType,
			"host":             acc.Host,
			"port":             acc.Port,
			"username":         acc.Username,
			"description":      acc.Description,
			"owner":            acc.Owner,
			"allowed_user_ids": allowedIDs,
			"need_review":      acc.NeedReview,
			"status":           acc.Status,
			"last_password_at": acc.LastPasswordAt,
			"created_at":       acc.CreatedAt,
			"updated_at":       acc.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(result))
}

func GetPrivilegeAccount(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var account models.PrivilegeAccount
	if err := database.DB.Preload("Owner").First(&account, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "特权账号不存在"))
		return
	}

	var allowedIDs []uint
	if account.AllowedUserIDs != "" {
		json.Unmarshal([]byte(account.AllowedUserIDs), &allowedIDs)
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"id":               account.ID,
		"account_name":     account.AccountName,
		"system_name":      account.SystemName,
		"system_type":      account.SystemType,
		"host":             account.Host,
		"port":             account.Port,
		"username":         account.Username,
		"description":      account.Description,
		"owner":            account.Owner,
		"allowed_user_ids": allowedIDs,
		"need_review":      account.NeedReview,
		"status":           account.Status,
		"last_password_at": account.LastPasswordAt,
		"created_at":       account.CreatedAt,
		"updated_at":       account.UpdatedAt,
	}))
}

func CreatePrivilegeAccount(c *gin.Context) {
	var req CreateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	userID, _ := c.Get("user_id")

	encryptedPass, err := utils.AesEncrypt(req.Password, config.AppConfig.AESKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "密码加密失败"))
		return
	}

	allowedIDsJSON, _ := json.Marshal(req.AllowedUserIDs)
	now := time.Now()
	needReview := true
	if req.NeedReview != nil {
		needReview = *req.NeedReview
	}

	port := req.Port
	if port == 0 {
		port = 22
	}

	account := models.PrivilegeAccount{
		AccountName:    req.AccountName,
		SystemName:     req.SystemName,
		SystemType:     req.SystemType,
		Host:           req.Host,
		Port:           port,
		Username:       req.Username,
		EncryptedPass:  encryptedPass,
		Description:    req.Description,
		OwnerID:        userID.(uint),
		AllowedUserIDs: string(allowedIDsJSON),
		NeedReview:     needReview,
		Status:         1,
		LastPasswordAt: &now,
	}

	if err := database.DB.Create(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "创建特权账号失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(account))
}

func UpdatePrivilegeAccount(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var account models.PrivilegeAccount
	if err := database.DB.First(&account, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "特权账号不存在"))
		return
	}

	var req UpdateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	if req.AccountName != "" {
		account.AccountName = req.AccountName
	}
	if req.SystemName != "" {
		account.SystemName = req.SystemName
	}
	if req.SystemType != "" {
		account.SystemType = req.SystemType
	}
	if req.Host != "" {
		account.Host = req.Host
	}
	if req.Port != nil {
		account.Port = *req.Port
	}
	if req.Username != "" {
		account.Username = req.Username
	}
	if req.Password != "" {
		encryptedPass, err := utils.AesEncrypt(req.Password, config.AppConfig.AESKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "密码加密失败"))
			return
		}
		account.EncryptedPass = encryptedPass
		now := time.Now()
		account.LastPasswordAt = &now
	}
	if req.Description != "" {
		account.Description = req.Description
	}
	if req.AllowedUserIDs != nil {
		allowedIDsJSON, _ := json.Marshal(req.AllowedUserIDs)
		account.AllowedUserIDs = string(allowedIDsJSON)
	}
	if req.NeedReview != nil {
		account.NeedReview = *req.NeedReview
	}
	if req.Status != nil {
		account.Status = *req.Status
	}

	if err := database.DB.Save(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "更新特权账号失败"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(account))
}

func DeletePrivilegeAccount(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	var pendingCount int64
	database.DB.Model(&models.OperationRequest{}).
		Where("privilege_acc_id = ? AND status IN ?", id, []string{"pending", "approved"}).
		Count(&pendingCount)
	if pendingCount > 0 {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "存在待处理或已批准的操作申请，无法删除"))
		return
	}

	if err := database.DB.Delete(&models.PrivilegeAccount{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "删除特权账号失败"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(nil))
}

func TestAccountConnection(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var account models.PrivilegeAccount
	if err := database.DB.First(&account, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "特权账号不存在"))
		return
	}

	password, err := utils.AesDecrypt(account.EncryptedPass, config.AppConfig.AESKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "密码解密失败"))
		return
	}

	result := simulateConnection(account.Host, account.Port, account.Username, password)
	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"success": result,
		"host":    account.Host,
		"port":    account.Port,
		"message": "连接测试完成",
	}))
}

func simulateConnection(host string, port int, username, password string) bool {
	time.Sleep(500 * time.Millisecond)
	return host != "" && port > 0 && username != "" && password != ""
}

func CheckAccountAccess(c *gin.Context, accountID uint, userID uint, role string) bool {
	if role == "super_admin" {
		return true
	}

	var account models.PrivilegeAccount
	if err := database.DB.First(&account, accountID).Error; err != nil {
		return false
	}

	if account.OwnerID == userID {
		return true
	}

	if account.AllowedUserIDs != "" {
		var allowedIDs []uint
		if err := json.Unmarshal([]byte(account.AllowedUserIDs), &allowedIDs); err == nil {
			for _, aid := range allowedIDs {
				if aid == userID {
					return true
				}
			}
		}
	}

	return false
}

func containsUserID(allowedStr string, userID uint) bool {
	var ids []uint
	json.Unmarshal([]byte(allowedStr), &ids)
	for _, id := range ids {
		if id == userID {
			return true
		}
	}
	return false
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
