package controllers

import (
	"fmt"
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

var allowedCommands = map[string]bool{
	"ls":       true,
	"pwd":      true,
	"date":     true,
	"whoami":   true,
	"ps":       true,
	"top":      true,
	"df":       true,
	"free":     true,
	"netstat":  true,
	"ss":       true,
	"systemctl": true,
	"service":  true,
	"cat":      true,
	"tail":     true,
	"head":     true,
	"grep":     true,
	"find":     true,
	"du":       true,
	"uname":    true,
	"uptime":   true,
	"hostname": true,
	"ip":       true,
	"ifconfig": true,
	"ping":     true,
	"curl":     true,
	"wget":     true,
}

var forbiddenPatterns = []string{
	"rm -rf /",
	"> /etc/",
	"chmod 777",
	"userdel",
	"passwd root",
	"mkfs",
	"dd if=/dev/zero",
	"wget http://malware",
	"curl http://malware",
	"/etc/shadow",
	"/etc/passwd >",
	"> ~/.ssh/authorized_keys",
}

func ExecuteOperation(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var operation models.OperationRequest
	if err := database.DB.Preload("PrivilegeAccount").First(&operation, id).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "操作申请不存在"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	if operation.RequesterID != userID.(uint) && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权执行此操作"))
		return
	}

	if operation.Status != "approved" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "操作申请未获批准，当前状态: "+operation.Status))
		return
	}

	if operation.ExecStatus == "executing" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "操作正在执行中，请等待"))
		return
	}

	now := time.Now()
	if operation.ExpectedEndTime != nil && now.After(*operation.ExpectedEndTime) {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "操作已超出允许执行时间窗口"))
		return
	}

	sessionID := utils.GenerateSessionID()
	session := models.OperationSession{
		SessionID:      sessionID,
		OperationReqID: operation.ID,
		StartTime:      now,
		SessionStatus:  "active",
	}
	database.DB.Create(&session)

	command := operation.OperationCommand
	if err := validateCommand(command); err != nil {
		operation.Status = "completed"
		operation.ExecStatus = "blocked"
		operation.ExecResult = "命令被安全策略拦截: " + err.Error()
		operation.ExecutedAt = &now
		database.DB.Save(&operation)

		session.SessionStatus = "blocked"
		endTime := time.Now()
		session.EndTime = &endTime
		session.SessionLog = "命令被拦截: " + err.Error()
		database.DB.Save(&session)

		c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
			"session_id": sessionID,
			"status":     "blocked",
			"result":     operation.ExecResult,
		}))
		return
	}

	operation.ExecStatus = "executing"
	database.DB.Save(&operation)

	password, _ := utils.AesDecrypt(operation.PrivilegeAccount.EncryptedPass, config.AppConfig.AESKey)
	result := simulateRemoteExecution(
		operation.PrivilegeAccount.Host,
		operation.PrivilegeAccount.Port,
		operation.PrivilegeAccount.Username,
		password,
		command,
	)

	execEndTime := time.Now()
	operation.Status = "completed"
	operation.ExecStatus = "success"
	if strings.Contains(result, "[ERROR]") {
		operation.ExecStatus = "failed"
	}
	operation.ExecResult = result
	operation.ExecutedAt = &execEndTime
	database.DB.Save(&operation)

	session.SessionStatus = "completed"
	session.EndTime = &execEndTime
	session.CommandCount = 1
	session.SessionLog = fmt.Sprintf("[%s] Execute: %s\nResult:\n%s", now.Format("2006-01-02 15:04:05"), command, result)
	database.DB.Save(&session)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":       sessionID,
		"operation_id":     operation.ID,
		"request_no":       operation.RequestNo,
		"status":           operation.ExecStatus,
		"account_name":     operation.PrivilegeAccount.AccountName,
		"system_name":      operation.PrivilegeAccount.SystemName,
		"target_host":      operation.PrivilegeAccount.Host,
		"target_port":      operation.PrivilegeAccount.Port,
		"executed_user":    operation.PrivilegeAccount.Username,
		"command_executed": command,
		"password_visible": false,
		"execution_result": result,
		"start_time":       now,
		"end_time":         execEndTime,
		"duration_ms":      execEndTime.Sub(now).Milliseconds(),
	}))
}

func ExecuteCommandInSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	var session models.OperationSession
	if err := database.DB.Where("session_id = ?", sessionID).
		Preload("OperationRequest").Preload("OperationRequest.PrivilegeAccount").
		First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "会话不存在"))
		return
	}

	if session.SessionStatus != "active" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "会话已结束，无法继续执行命令"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	if session.OperationRequest.RequesterID != userID.(uint) && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权在此会话中执行命令"))
		return
	}

	now := time.Now()
	if session.OperationRequest.ExpectedEndTime != nil && now.After(*session.OperationRequest.ExpectedEndTime) {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "已超出允许执行时间窗口，会话已自动关闭"))
		session.SessionStatus = "expired"
		endTime := time.Now()
		session.EndTime = &endTime
		database.DB.Save(&session)
		return
	}

	var req OpExecuteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误"))
		return
	}

	if err := validateCommand(req.Command); err != nil {
		c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
			"status": "blocked",
			"result": "命令被安全策略拦截: " + err.Error(),
		}))
		return
	}

	password, _ := utils.AesDecrypt(session.OperationRequest.PrivilegeAccount.EncryptedPass, config.AppConfig.AESKey)
	result := simulateRemoteExecution(
		session.OperationRequest.PrivilegeAccount.Host,
		session.OperationRequest.PrivilegeAccount.Port,
		session.OperationRequest.PrivilegeAccount.Username,
		password,
		req.Command,
	)

	session.CommandCount++
	session.SessionLog += fmt.Sprintf("\n[%s] Execute: %s\nResult:\n%s", now.Format("2006-01-02 15:04:05"), req.Command, result)
	database.DB.Save(&session)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":       sessionID,
		"command_executed": req.Command,
		"status":           "success",
		"password_visible": false,
		"execution_result": result,
		"command_count":    session.CommandCount,
	}))
}

func CloseOperationSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	var session models.OperationSession
	if err := database.DB.Where("session_id = ?", sessionID).First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "会话不存在"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")

	var operation models.OperationRequest
	database.DB.First(&operation, session.OperationReqID)
	if operation.RequesterID != userID.(uint) && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权关闭此会话"))
		return
	}

	session.SessionStatus = "closed"
	endTime := time.Now()
	session.EndTime = &endTime
	database.DB.Save(&session)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id": sessionID,
		"status":     "closed",
		"duration":   endTime.Sub(session.StartTime).String(),
		"total_commands": session.CommandCount,
	}))
}

func GetOperationSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	var session models.OperationSession
	if err := database.DB.Where("session_id = ?", sessionID).
		Preload("OperationRequest").Preload("OperationRequest.PrivilegeAccount").
		First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "会话不存在"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":      session.SessionID,
		"status":          session.SessionStatus,
		"start_time":      session.StartTime,
		"end_time":        session.EndTime,
		"command_count":   session.CommandCount,
		"operation":       session.OperationRequest,
		"session_log":     session.SessionLog,
		"password_visible": false,
	}))
}

func validateCommand(command string) error {
	lowerCmd := strings.ToLower(command)
	for _, pattern := range forbiddenPatterns {
		if strings.Contains(lowerCmd, strings.ToLower(pattern)) {
			return fmt.Errorf("命令包含危险操作: %s", pattern)
		}
	}
	return nil
}

func simulateRemoteExecution(host string, port int, username, password, command string) string {
	time.Sleep(300 * time.Millisecond)

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Connected to %s:%d as %s (password masked, never exposed)\n", host, port, username))
	output.WriteString(fmt.Sprintf("$ %s\n", command))

	fields := strings.Fields(command)
	if len(fields) == 0 {
		return output.String()
	}

	baseCmd := fields[0]

	switch baseCmd {
	case "ls":
		output.WriteString("total 32\n")
		output.WriteString("drwxr-xr-x  2 root root 4096 Jun 20 10:00 bin\n")
		output.WriteString("drwxr-xr-x  3 root root 4096 Jun 20 10:00 etc\n")
		output.WriteString("drwxr-xr-x  2 root root 4096 Jun 20 10:00 home\n")
		output.WriteString("drwxr-xr-x  8 root root 4096 Jun 20 10:00 var\n")
		output.WriteString("-rw-r--r--  1 root root  512 Jun 20 10:00 config.yaml\n")
	case "pwd":
		output.WriteString("/opt/app\n")
	case "date":
		output.WriteString(time.Now().Format("Mon Jan 2 15:04:05 MST 2006") + "\n")
	case "whoami":
		output.WriteString(username + "\n")
	case "df":
		output.WriteString("Filesystem      Size  Used Avail Use% Mounted on\n")
		output.WriteString("/dev/sda1        50G   28G   20G  59% /\n")
		output.WriteString("tmpfs           3.9G     0  3.9G   0% /dev/shm\n")
	case "free":
		output.WriteString("              total        used        free      shared  buff/cache   available\n")
		output.WriteString("Mem:        7908352     3421568     1234567       65432     3252217     4256789\n")
		output.WriteString("Swap:       2097148           0     2097148\n")
	case "ps":
		output.WriteString("  PID TTY          TIME CMD\n")
		output.WriteString("    1 ?        00:01:23 systemd\n")
		output.WriteString("  234 ?        00:00:45 nginx\n")
		output.WriteString("  567 ?        00:12:34 java\n")
		output.WriteString("  890 pts/0    00:00:00 bash\n")
	case "uptime":
		output.WriteString(fmt.Sprintf(" %s up 15 days, 3:42,  3 users,  load average: 0.25, 0.38, 0.41\n",
			time.Now().Format("15:04:05")))
	case "systemctl":
		if len(fields) >= 2 && fields[1] == "status" {
			svc := "application"
			if len(fields) >= 3 {
				svc = fields[2]
			}
			output.WriteString(fmt.Sprintf("● %s.service - Application Service\n", svc))
			output.WriteString("   Loaded: loaded (/etc/systemd/system/app.service; enabled; vendor preset: disabled)\n")
			output.WriteString("   Active: active (running) since Mon 2026-06-20 08:00:00 CST; 2h ago\n")
			output.WriteString(" Main PID: 12345 (java)\n")
			output.WriteString("   Tasks: 58 (limit: 4096)\n")
			output.WriteString("   Memory: 1.2G\n")
			output.WriteString("   CGroup: /system.slice/app.service\n")
			output.WriteString("           └─12345 /usr/bin/java -jar app.jar\n")
		} else if len(fields) >= 2 && fields[1] == "restart" {
			svc := "application"
			if len(fields) >= 3 {
				svc = fields[2]
			}
			output.WriteString(fmt.Sprintf("Restarting %s.service...\n", svc))
			output.WriteString(fmt.Sprintf("%s.service restarted successfully.\n", svc))
		} else {
			output.WriteString("[ERROR] Invalid systemctl command\n")
		}
	case "cat", "tail", "head":
		if len(fields) >= 2 {
			output.WriteString(fmt.Sprintf("===== Content of %s =====\n", fields[len(fields)-1]))
			output.WriteString("2026-06-20 10:00:01 [INFO] Application started successfully\n")
			output.WriteString("2026-06-20 10:00:05 [INFO] Connected to database\n")
			output.WriteString("2026-06-20 10:05:23 [INFO] Processing request #12345\n")
			output.WriteString("2026-06-20 10:10:45 [WARN] High memory usage detected: 85%\n")
			output.WriteString("2026-06-20 10:15:00 [INFO] Health check passed\n")
			output.WriteString("================================\n")
		}
	case "ping":
		output.WriteString("PING localhost (127.0.0.1) 56(84) bytes of data.\n")
		for i := 1; i <= 4; i++ {
			output.WriteString(fmt.Sprintf("64 bytes from localhost (127.0.0.1): icmp_seq=%d ttl=64 time=0.0%d ms\n", i, i*12))
		}
		output.WriteString("\n--- localhost ping statistics ---\n")
		output.WriteString("4 packets transmitted, 4 received, 0% packet loss, time 3001ms\n")
	case "hostname":
		output.WriteString(fmt.Sprintf("prod-%s-%s\n", host, strings.ReplaceAll(host, ".", "-")))
	case "uname":
		output.WriteString("Linux prod-server 5.14.0-284.el9.x86_64 #1 SMP x86_64 GNU/Linux\n")
	case "netstat", "ss":
		output.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
		output.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n")
	default:
		output.WriteString(fmt.Sprintf("[Command executed successfully on %s]\n", host))
		output.WriteString("Command output (simulated):\n")
		output.WriteString("Operation completed. For detailed output, please check the operation session log.\n")
	}

	output.WriteString("\n[Connection closed by privileged vault]\n")
	return output.String()
}

func ListMyOperations(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var operations []models.OperationRequest
	database.DB.Preload("Requester").Preload("PrivilegeAccount").Preload("Reviewer").
		Where("requester_id = ?", userID.(uint)).
		Order("created_at DESC").
		Find(&operations)

	c.JSON(http.StatusOK, utils.SuccessResponse(operations))
}
