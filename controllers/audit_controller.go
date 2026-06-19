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

func ListAuditLogs(c *gin.Context) {
	var logs []models.AuditLog
	query := database.DB.Preload("User")

	action := c.Query("action")
	if action != "" {
		query = query.Where("action LIKE ?", "%"+action+"%")
	}

	userID := c.Query("user_id")
	if userID != "" {
		id, _ := strconv.Atoi(userID)
		query = query.Where("user_id = ?", id)
	}

	result := c.Query("result")
	if result != "" {
		r, _ := strconv.Atoi(result)
		query = query.Where("result = ?", r)
	}

	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	if startDate != "" && endDate != "" {
		start, _ := time.Parse("2006-01-02", startDate)
		end, _ := time.Parse("2006-01-02", endDate)
		end = end.Add(24 * time.Hour)
		query = query.Where("created_at BETWEEN ? AND ?", start, end)
	}

	query = query.Order("created_at DESC")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 500 {
		pageSize = 50
	}

	var total int64
	query.Model(&models.AuditLog{}).Count(&total)
	query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"list":       logs,
		"total":      total,
		"page":       page,
		"page_size":  pageSize,
	}))
}

func GetAuditLog(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var log models.AuditLog
	if err := database.DB.Preload("User").First(&log, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "审计日志不存在"))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse(log))
}

func GetAuditStatistics(c *gin.Context) {
	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	last7Days := time.Now().AddDate(0, 0, -7)
	last30Days := time.Now().AddDate(0, 0, -30)

	var totalLogs7Days int64
	database.DB.Model(&models.AuditLog{}).Where("created_at >= ?", last7Days).Count(&totalLogs7Days)

	var totalLogs30Days int64
	database.DB.Model(&models.AuditLog{}).Where("created_at >= ?", last30Days).Count(&totalLogs30Days)

	var failedLogs30Days int64
	database.DB.Model(&models.AuditLog{}).Where("created_at >= ? AND result = 0", last30Days).Count(&failedLogs30Days)

	var uniqueUsers int64
	database.DB.Model(&models.AuditLog{}).Where("created_at >= ?", last30Days).Distinct("user_id").Count(&uniqueUsers)

	actionTypeStats := make([]map[string]interface{}, 0)
	rows, _ := database.DB.Model(&models.AuditLog{}).
		Select("action, COUNT(*) as count").
		Where("created_at >= ?", last30Days).
		Group("action").
		Order("count DESC").
		Limit(10).
		Rows()
	defer rows.Close()
	for rows.Next() {
		var action string
		var count int64
		rows.Scan(&action, &count)
		actionTypeStats = append(actionTypeStats, map[string]interface{}{
			"action": action,
			"count":  count,
		})
	}

	dailyStats := make([]map[string]interface{}, 0)
	dailyRows, _ := database.DB.Model(&models.AuditLog{}).
		Select("DATE(created_at) as date, COUNT(*) as count").
		Where("created_at >= ?", last7Days).
		Group("DATE(created_at)").
		Order("date DESC").
		Rows()
	defer dailyRows.Close()
	for dailyRows.Next() {
		var date string
		var count int64
		dailyRows.Scan(&date, &count)
		dailyStats = append(dailyStats, map[string]interface{}{
			"date":  date,
			"count": count,
		})
	}

	var accountCount int64
	database.DB.Model(&models.PrivilegeAccount{}).Count(&accountCount)

	var pendingRequests int64
	database.DB.Model(&models.OperationRequest{}).Where("status = ?", "pending").Count(&pendingRequests)

	var activeSessions int64
	database.DB.Model(&models.OperationSession{}).Where("session_status = ?", "active").Count(&activeSessions)

	var totalOperations int64
	database.DB.Model(&models.OperationRequest{}).Count(&totalOperations)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"current_user": map[string]interface{}{
			"user_id": userID,
			"role":    role,
		},
		"audit_statistics": map[string]interface{}{
			"logs_last_7_days":   totalLogs7Days,
			"logs_last_30_days":  totalLogs30Days,
			"failed_operations":  failedLogs30Days,
			"unique_active_users": uniqueUsers,
			"top_actions":        actionTypeStats,
			"daily_activity":     dailyStats,
		},
		"business_overview": map[string]interface{}{
			"total_privilege_accounts": accountCount,
			"pending_approval_requests": pendingRequests,
			"active_execution_sessions": activeSessions,
			"total_operation_requests":  totalOperations,
		},
	}))
}
