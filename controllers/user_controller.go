package controllers

import (
	"net/http"
	"privilege-vault/database"
	"privilege-vault/models"
	"privilege-vault/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
	RealName string `json:"real_name"`
	Role     string `json:"role" binding:"required,oneof=super_admin reviewer operator"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
}

type UpdateUserRequest struct {
	RealName string `json:"real_name"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Status   *int   `json:"status"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	var user models.User
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(401, "用户名或密码错误"))
		return
	}

	if user.Status != 1 {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "账号已被禁用"))
		return
	}

	if !utils.CheckPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(401, "用户名或密码错误"))
		return
	}

	token, err := utils.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "生成令牌失败"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"token": token,
		"user": gin.H{
			"id":        user.ID,
			"username":  user.Username,
			"real_name": user.RealName,
			"role":      user.Role,
			"email":     user.Email,
			"phone":     user.Phone,
		},
	}))
}

func GetCurrentUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "用户不存在"))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse(user))
}

func ListUsers(c *gin.Context) {
	var users []models.User
	query := database.DB

	role := c.Query("role")
	if role != "" {
		query = query.Where("role = ?", role)
	}

	status := c.Query("status")
	if status != "" {
		s, _ := strconv.Atoi(status)
		query = query.Where("status = ?", s)
	}

	keyword := c.Query("keyword")
	if keyword != "" {
		query = query.Where("username LIKE ? OR real_name LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	query.Find(&users)
	c.JSON(http.StatusOK, utils.SuccessResponse(users))
}

func GetUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "用户不存在"))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse(user))
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	var existing models.User
	if database.DB.Where("username = ?", req.Username).First(&existing).Error == nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "用户名已存在"))
		return
	}

	hashedPass, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "密码加密失败"))
		return
	}

	user := models.User{
		Username: req.Username,
		Password: hashedPass,
		RealName: req.RealName,
		Role:     req.Role,
		Email:    req.Email,
		Phone:    req.Phone,
		Status:   1,
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "创建用户失败: "+err.Error()))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(user))
}

func UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "用户不存在"))
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	if req.RealName != "" {
		user.RealName = req.RealName
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Phone != "" {
		user.Phone = req.Phone
	}
	if req.Status != nil {
		user.Status = *req.Status
	}

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "更新用户失败"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(user))
}

func DeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	currentUserID, _ := c.Get("user_id")
	if uint(id) == currentUserID.(uint) {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "不能删除自己"))
		return
	}

	if err := database.DB.Delete(&models.User{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "删除用户失败"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(nil))
}

func ChangePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "用户不存在"))
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	if !utils.CheckPassword(req.OldPassword, user.Password) {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "原密码错误"))
		return
	}

	hashedPass, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "密码加密失败"))
		return
	}

	user.Password = hashedPass
	database.DB.Save(&user)

	c.JSON(http.StatusOK, utils.SuccessResponse(nil))
}
