package controllers

import (
	"net/http"
	"privilege-vault/database"
	"privilege-vault/models"
	"privilege-vault/utils"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type OpCreateRequest struct {
	PrivilegeAccID    uint       `json:"privilege_acc_id" binding:"required"`
	OperationType     string     `json:"operation_type" binding:"required,oneof=command_exec file_transfer service_restart config_modify system_check other"`
	OperationCommand  string     `json:"operation_command" binding:"required"`
	Reason            string     `json:"reason" binding:"required"`
	ExpectedStartTime *time.Time `json:"expected_start_time"`
	ExpectedEndTime   *time.Time `json:"expected_end_time"`
}

type OpReviewRequest struct {
	Approved      bool   `json:"approved" binding:"required"`
	ReviewComment string `json:"review_comment"`
}

type OpExecuteRequest struct {
	Command string `json:"command"`
}

func CreateOperationRequest(c *gin.Context) {
	var req OpCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	var account models.PrivilegeAccount
	if err := database.DB.First(&account, req.PrivilegeAccID).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "特权账号不存在"))
		return
	}

	if account.Status != 1 {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "特权账号已被禁用"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	if !CheckAccountAccess(c, req.PrivilegeAccID, userID.(uint), role.(string)) {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权申请此特权账号的操作"))
		return
	}

	requestNo := utils.GenerateRequestNo()

	status := "pending"
	if !account.NeedReview || role.(string) == "super_admin" {
		status = "approved"
	}

	startTime := req.ExpectedStartTime
	if startTime == nil {
		now := time.Now()
		startTime = &now
	}

	endTime := req.ExpectedEndTime
	if endTime == nil {
		t := startTime.Add(2 * time.Hour)
		endTime = &t
	}

	operation := models.OperationRequest{
		RequestNo:         requestNo,
		RequesterID:       userID.(uint),
		PrivilegeAccID:    req.PrivilegeAccID,
		OperationType:     req.OperationType,
		OperationCommand:  req.OperationCommand,
		Reason:            req.Reason,
		ExpectedStartTime: startTime,
		ExpectedEndTime:   endTime,
		Status:            status,
	}

	if err := database.DB.Create(&operation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "创建操作申请失败: "+err.Error()))
		return
	}

	database.DB.Preload("Requester").Preload("PrivilegeAccount").First(&operation, operation.ID)

	c.JSON(http.StatusOK, utils.SuccessResponse(operation))
}

func ListOperationRequests(c *gin.Context) {
	var operations []models.OperationRequest
	query := database.DB.Preload("Requester").Preload("PrivilegeAccount").Preload("Reviewer")

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	switch role.(string) {
	case "operator":
		query = query.Where("requester_id = ?", userID.(uint))
	case "reviewer":
		query = query.Where("status = ? OR reviewer_id = ? OR requester_id = ?",
			"pending", userID.(uint), userID.(uint))
	}

	status := c.Query("status")
	if status != "" {
		query = query.Where("status = ?", status)
	}

	accID := c.Query("privilege_acc_id")
	if accID != "" {
		id, _ := strconv.Atoi(accID)
		query = query.Where("privilege_acc_id = ?", id)
	}

	opType := c.Query("operation_type")
	if opType != "" {
		query = query.Where("operation_type = ?", opType)
	}

	query = query.Order("created_at DESC")
	query.Find(&operations)

	c.JSON(http.StatusOK, utils.SuccessResponse(operations))
}

func GetOperationRequest(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var operation models.OperationRequest
	if err := database.DB.Preload("Requester").Preload("PrivilegeAccount").Preload("Reviewer").First(&operation, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "操作申请不存在"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(operation))
}

func ReviewOperationRequest(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var operation models.OperationRequest
	if err := database.DB.First(&operation, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "操作申请不存在"))
		return
	}

	if operation.Status != "pending" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "当前申请状态不允许审批"))
		return
	}

	var req OpReviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误: "+err.Error()))
		return
	}

	userID, _ := c.Get("user_id")
	now := time.Now()
	reviewerID := userID.(uint)

	if req.Approved {
		operation.Status = "approved"
	} else {
		operation.Status = "rejected"
	}
	operation.ReviewerID = &reviewerID
	operation.ReviewComment = req.ReviewComment
	operation.ReviewedAt = &now

	if err := database.DB.Save(&operation).Error; err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(500, "审批失败"))
		return
	}

	database.DB.Preload("Requester").Preload("PrivilegeAccount").Preload("Reviewer").First(&operation, id)
	c.JSON(http.StatusOK, utils.SuccessResponse(operation))
}

func CancelOperationRequest(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var operation models.OperationRequest
	if err := database.DB.First(&operation, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "操作申请不存在"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	if operation.RequesterID != userID.(uint) && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权取消此申请"))
		return
	}

	if operation.Status != "pending" && operation.Status != "approved" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "当前状态不允许取消"))
		return
	}

	operation.Status = "cancelled"
	now := time.Now()
	operation.ReviewedAt = &now
	operation.ReviewComment = "申请人取消"

	database.DB.Save(&operation)
	c.JSON(http.StatusOK, utils.SuccessResponse(operation))
}

func GetMyPendingReviews(c *gin.Context) {
	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	var operations []models.OperationRequest
	query := database.DB.Preload("Requester").Preload("PrivilegeAccount").
		Where("status = ?", "pending")

	if role.(string) != "super_admin" {
		query = query.Joins("LEFT JOIN privilege_accounts ON privilege_accounts.id = operation_requests.privilege_acc_id").
			Where("privilege_accounts.owner_id = ?", userID.(uint))
	}

	query.Order("created_at DESC").Find(&operations)
	c.JSON(http.StatusOK, utils.SuccessResponse(operations))
}
