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

var highRiskCommands = map[string]string{
	"rm":       "high",
	"mkfs":     "critical",
	"dd":       "high",
	"chmod":    "medium",
	"chown":    "medium",
	"userdel":  "high",
	"usermod":  "medium",
	"passwd":   "high",
	">":        "medium",
	">>":       "low",
	"reboot":   "high",
	"shutdown": "critical",
	"init":     "high",
	"kill":     "medium",
	"killall":  "medium",
}

var forbiddenPatterns = []string{
	"rm -rf /",
	"rm -rf /*",
	"> /etc/passwd",
	"> /etc/shadow",
	"chmod 777 /etc",
	"mkfs.ext",
	"dd if=/dev/zero",
	"> ~/.ssh/authorized_keys",
	"| bash",
	"| sh",
	"curl.*|.*sh",
	"wget.*-O.*sh",
	"/etc/shadow",
	"cat /etc/passwd",
}

func recordCommand(sessionID string, opReqID uint, seq int, operatorID uint, command string, output string, durationMs int64, blocked bool, blockReason string, dangerLevel string) *models.SessionCommandRecord {
	record := &models.SessionCommandRecord{
		SessionID:      sessionID,
		OperationReqID: opReqID,
		Sequence:       seq,
		OperatorID:     operatorID,
		Command:        command,
		CommandType:    classifyCommand(command),
		Output:         output,
		OutputSize:     len(output),
		ExecutedAt:     time.Now(),
		DurationMs:     durationMs,
		IsBlocked:      blocked,
		BlockReason:    blockReason,
		IsDangerous:    dangerLevel != "low",
		DangerLevel:    dangerLevel,
		ExitCode:       0,
		CreatedAt:      time.Now(),
	}
	if blocked {
		record.ExitCode = 1
	}
	database.DB.Create(record)
	return record
}

func classifyCommand(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "unknown"
	}
	base := fields[0]

	switch {
	case base == "cd" || base == "pwd" || base == "ls" || base == "find":
		return "file_browse"
	case base == "cat" || base == "tail" || base == "head" || base == "more" || base == "less":
		return "file_read"
	case strings.Contains(command, ">") || strings.Contains(command, ">>") || base == "echo" || base == "tee":
		return "file_write"
	case base == "systemctl" || base == "service" || base == "chkconfig":
		return "service_manage"
	case base == "ps" || base == "top" || base == "htop" || base == "kill" || base == "killall":
		return "process_manage"
	case base == "useradd" || base == "userdel" || base == "usermod" || base == "passwd":
		return "user_manage"
	case base == "chmod" || base == "chown" || base == "chgrp":
		return "permission_change"
	case base == "rm" || base == "mv" || base == "cp" || base == "mkdir" || base == "rmdir":
		return "file_operation"
	case base == "ifconfig" || base == "ip" || base == "netstat" || base == "ss" || base == "ping":
		return "network_check"
	case base == "df" || base == "du" || base == "free" || base == "uname" || base == "uptime":
		return "system_info"
	default:
		return "other"
	}
}

func checkDangerLevel(command string) string {
	lowerCmd := strings.ToLower(command)
	fields := strings.Fields(lowerCmd)
	if len(fields) == 0 {
		return "low"
	}

	base := fields[0]
	if level, exists := highRiskCommands[base]; exists {
		return level
	}

	for _, pattern := range forbiddenPatterns {
		if strings.Contains(lowerCmd, pattern) {
			return "critical"
		}
	}

	if strings.Contains(lowerCmd, "sudo") {
		return "high"
	}
	if strings.Contains(lowerCmd, "|") && (strings.Contains(lowerCmd, "bash") || strings.Contains(lowerCmd, "sh")) {
		return "critical"
	}

	return "low"
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
	uid := userID.(uint)

	if operation.RequesterID != uid && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权执行此操作"))
		return
	}

	if operation.Status != "approved" {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "操作申请未获批准，当前状态: "+operation.Status))
		return
	}

	now := time.Now()
	if operation.ExpectedEndTime != nil && now.After(*operation.ExpectedEndTime) {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "操作已超出允许执行时间窗口"))
		return
	}

	var activeSession models.OperationSession
	sessionExists := false
	result := database.DB.Where("operation_req_id = ? AND session_status = ?", operation.ID, "active").First(&activeSession)
	if result.Error == nil {
		sessionExists = true
	}

	var session models.OperationSession
	if sessionExists {
		session = activeSession
	} else {
		sessionID := utils.GenerateSessionID()
		clientIP := c.ClientIP()

		session = models.OperationSession{
			SessionID:      sessionID,
			OperationReqID: operation.ID,
			OperatorID:     uid,
			StartTime:      now,
			SessionStatus:  "active",
			TermType:       "web",
			ClientIP:       clientIP,
		}
		database.DB.Create(&session)
	}

	command := operation.OperationCommand
	dangerLevel := checkDangerLevel(command)

	if err := validateCommand(command); err != nil {
		recordCommand(session.SessionID, operation.ID, session.CommandCount+1, uid, command, "", 0, true, err.Error(), dangerLevel)

		operation.Status = "completed"
		operation.ExecStatus = "blocked"
		operation.ExecResult = "命令被安全策略拦截: " + err.Error()
		operation.ExecutedAt = &now
		database.DB.Save(&operation)

		c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
			"session_id":     session.SessionID,
			"status":         "blocked",
			"blocked":        true,
			"block_reason":   err.Error(),
			"danger_level":   dangerLevel,
			"password_visible": false,
		}))
		return
	}

	password, _ := utils.AesDecrypt(operation.PrivilegeAccount.EncryptedPass, config.AppConfig.AESKey)

	execStartTime := time.Now()
	resultOutput := simulateRemoteExecution(
		operation.PrivilegeAccount.Host,
		operation.PrivilegeAccount.Port,
		operation.PrivilegeAccount.Username,
		password,
		command,
	)
	execDuration := time.Since(execStartTime).Milliseconds()

	session.CommandCount++
	session.SessionLog += fmt.Sprintf("\n[%s] $ %s\n%s", execStartTime.Format("2006-01-02 15:04:05"), command, resultOutput)
	database.DB.Save(&session)

	recordCommand(session.SessionID, operation.ID, session.CommandCount, uid, command, resultOutput, execDuration, false, "", dangerLevel)

	operation.ExecStatus = "executing"
	operation.ExecResult = resultOutput
	operation.ExecutedAt = &now
	database.DB.Save(&operation)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":       session.SessionID,
		"operation_id":     operation.ID,
		"request_no":       operation.RequestNo,
		"status":           "success",
		"exec_status":      "session_active",
		"account_name":     operation.PrivilegeAccount.AccountName,
		"system_name":      operation.PrivilegeAccount.SystemName,
		"target_host":      operation.PrivilegeAccount.Host,
		"target_port":      operation.PrivilegeAccount.Port,
		"executed_user":    operation.PrivilegeAccount.Username,
		"command_executed": command,
		"command_type":     classifyCommand(command),
		"danger_level":     dangerLevel,
		"password_visible": false,
		"execution_result": resultOutput,
		"command_sequence": session.CommandCount,
		"start_time":       execStartTime,
		"duration_ms":      execDuration,
		"session_active":   true,
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
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "会话已结束(状态: "+session.SessionStatus+")，无法继续执行命令"))
		return
	}

	userID, _ := c.Get("user_id")
	role, _ := c.Get("role")
	uid := userID.(uint)

	if session.OperatorID != uid && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权在此会话中执行命令"))
		return
	}

	now := time.Now()
	if session.OperationRequest.ExpectedEndTime != nil && now.After(*session.OperationRequest.ExpectedEndTime) {
		session.SessionStatus = "expired"
		endTime := time.Now()
		session.EndTime = &endTime
		database.DB.Save(&session)
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "已超出允许执行时间窗口，会话已自动关闭"))
		return
	}

	var req OpExecuteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse(400, "请求参数错误"))
		return
	}

	dangerLevel := checkDangerLevel(req.Command)

	if err := validateCommand(req.Command); err != nil {
		recordCommand(session.SessionID, session.OperationReqID, session.CommandCount+1, uid, req.Command, "", 0, true, err.Error(), dangerLevel)
		session.CommandCount++
		session.SessionLog += fmt.Sprintf("\n[%s] $ %s\n[BLOCKED] %s", now.Format("2006-01-02 15:04:05"), req.Command, err.Error())
		database.DB.Save(&session)

		c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
			"session_id":       sessionID,
			"command_executed": req.Command,
			"status":           "blocked",
			"block_reason":     err.Error(),
			"danger_level":     dangerLevel,
			"password_visible": false,
			"command_sequence": session.CommandCount,
			"is_blocked":       true,
		}))
		return
	}

	password, _ := utils.AesDecrypt(session.OperationRequest.PrivilegeAccount.EncryptedPass, config.AppConfig.AESKey)

	execStartTime := time.Now()
	resultOutput := simulateRemoteExecution(
		session.OperationRequest.PrivilegeAccount.Host,
		session.OperationRequest.PrivilegeAccount.Port,
		session.OperationRequest.PrivilegeAccount.Username,
		password,
		req.Command,
	)
	execDuration := time.Since(execStartTime).Milliseconds()

	session.CommandCount++
	session.SessionLog += fmt.Sprintf("\n[%s] $ %s\n%s", execStartTime.Format("2006-01-02 15:04:05"), req.Command, resultOutput)
	database.DB.Save(&session)

	recordCommand(session.SessionID, session.OperationReqID, session.CommandCount, uid, req.Command, resultOutput, execDuration, false, "", dangerLevel)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":       sessionID,
		"command_executed": req.Command,
		"command_type":     classifyCommand(req.Command),
		"danger_level":     dangerLevel,
		"status":           "success",
		"password_visible": false,
		"execution_result": resultOutput,
		"command_sequence": session.CommandCount,
		"duration_ms":      execDuration,
		"session_active":   true,
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
	uid := userID.(uint)

	var operation models.OperationRequest
	database.DB.First(&operation, session.OperationReqID)
	if session.OperatorID != uid && role.(string) != "super_admin" {
		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "无权关闭此会话"))
		return
	}

	if session.SessionStatus == "active" {
		session.SessionStatus = "closed"
		endTime := time.Now()
		session.EndTime = &endTime
		session.TotalDurationMs = endTime.Sub(session.StartTime).Milliseconds()
		database.DB.Save(&session)

		if operation.Status == "approved" || operation.ExecStatus == "executing" {
			operation.Status = "completed"
			operation.ExecStatus = "completed"
			database.DB.Save(&operation)
		}
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":      sessionID,
		"status":          session.SessionStatus,
		"start_time":      session.StartTime,
		"end_time":        session.EndTime,
		"total_commands":  session.CommandCount,
		"duration_ms":     session.TotalDurationMs,
		"duration_human":  time.Duration(session.TotalDurationMs * 1e6).String(),
	}))
}

func GetOperationSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	var session models.OperationSession
	if err := database.DB.Where("session_id = ?", sessionID).
		Preload("OperationRequest").Preload("OperationRequest.PrivilegeAccount").Preload("Operator").
		First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "会话不存在"))
		return
	}

	var commandCount int64
	database.DB.Model(&models.SessionCommandRecord{}).
		Where("session_id = ?", sessionID).Count(&commandCount)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":       session.SessionID,
		"status":           session.SessionStatus,
		"start_time":       session.StartTime,
		"end_time":         session.EndTime,
		"command_count":    session.CommandCount,
		"total_duration_ms": session.TotalDurationMs,
		"operator":         session.Operator,
		"operation":        session.OperationRequest,
		"term_type":        session.TermType,
		"client_ip":        session.ClientIP,
		"password_visible": false,
		"session_log":      session.SessionLog,
	}))
}

func GetSessionCommandRecords(c *gin.Context) {
	sessionID := c.Param("session_id")

	var records []models.SessionCommandRecord
	query := database.DB.Preload("Operator").Where("session_id = ?", sessionID).Order("sequence ASC")

	dangerLevel := c.Query("danger_level")
	if dangerLevel != "" {
		query = query.Where("danger_level = ?", dangerLevel)
	}

	blocked := c.Query("blocked")
	if blocked != "" {
		b := blocked == "true"
		query = query.Where("is_blocked = ?", b)
	}

	query.Find(&records)

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id": sessionID,
		"total":      len(records),
		"commands":   records,
	}))
}

func GetSessionCommandRecord(c *gin.Context) {
	recordID, _ := strconv.Atoi(c.Param("record_id"))
	var record models.SessionCommandRecord
	if err := database.DB.Preload("Operator").First(&record, recordID).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "命令记录不存在"))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(record))
}

func PlaybackSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	var session models.OperationSession
	if err := database.DB.Where("session_id = ?", sessionID).
		Preload("OperationRequest").Preload("OperationRequest.PrivilegeAccount").Preload("Operator").
		First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse(404, "会话不存在"))
		return
	}

	var records []models.SessionCommandRecord
	database.DB.Where("session_id = ?", sessionID).
		Order("sequence ASC").
		Find(&records)

	dangerousCount := 0
	blockedCount := 0
	for _, r := range records {
		if r.IsDangerous {
			dangerousCount++
		}
		if r.IsBlocked {
			blockedCount++
		}
	}

	playbackFrames := make([]gin.H, 0)
	cumulativeOutput := ""
	for _, record := range records {
		cumulativeOutput += fmt.Sprintf("$ %s\n%s\n", record.Command, record.Output)
		playbackFrames = append(playbackFrames, gin.H{
			"sequence":       record.Sequence,
			"timestamp":      record.ExecutedAt,
			"command":        record.Command,
			"command_type":   record.CommandType,
			"output":         record.Output,
			"output_size":    record.OutputSize,
			"duration_ms":    record.DurationMs,
			"is_blocked":     record.IsBlocked,
			"block_reason":   record.BlockReason,
			"is_dangerous":   record.IsDangerous,
			"danger_level":   record.DangerLevel,
			"operator_id":    record.OperatorID,
			"cumulative_screen": cumulativeOutput,
		})
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(gin.H{
		"session_id":      session.SessionID,
		"session_status":  session.SessionStatus,
		"start_time":      session.StartTime,
		"end_time":        session.EndTime,
		"operator":        session.Operator,
		"target_host":     session.OperationRequest.PrivilegeAccount.Host,
		"target_user":     session.OperationRequest.PrivilegeAccount.Username,
		"total_commands":  len(records),
		"dangerous_count": dangerousCount,
		"blocked_count":   blockedCount,
		"total_duration_ms": session.TotalDurationMs,
		"password_visible": false,
		"playback_frames": playbackFrames,
		"full_session_log": session.SessionLog,
	}))
}

func validateCommand(command string) error {
	lowerCmd := strings.ToLower(command)
	for _, pattern := range forbiddenPatterns {
		if strings.Contains(lowerCmd, pattern) {
			return fmt.Errorf("命令包含危险操作模式: %s", pattern)
		}
	}
	return nil
}

func simulateRemoteExecution(host string, port int, username, password, command string) string {
	time.Sleep(200 * time.Millisecond)

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Connected to %s:%d as %s (password: *** masked ***)\n", host, port, username))
	output.WriteString(fmt.Sprintf("$ %s\n", command))

	fields := strings.Fields(command)
	if len(fields) == 0 {
		return output.String()
	}

	baseCmd := fields[0]

	switch baseCmd {
	case "ls":
		output.WriteString("total 40\n")
		output.WriteString("drwxr-xr-x  2 root root 4096 Jun 20 08:00 bin\n")
		output.WriteString("drwxr-xr-x  5 root root 4096 Jun 20 08:00 etc\n")
		output.WriteString("drwxr-xr-x  3 root root 4096 Jun 20 08:00 home\n")
		output.WriteString("drwxr-xr-x  2 root root 4096 Jun 20 08:00 logs\n")
		output.WriteString("drwxr-xr-x  8 root root 4096 Jun 20 08:00 var\n")
		output.WriteString("-rw-r--r--  1 root root  512 Jun 20 08:00 config.yaml\n")
		output.WriteString("-rwxr-xr-x  1 root root 8192 Jun 20 08:00 start.sh\n")
	case "pwd":
		output.WriteString("/opt/application\n")
	case "date":
		output.WriteString(time.Now().Format("Mon Jan 2 15:04:05 MST 2006") + "\n")
	case "whoami":
		output.WriteString(username + "\n")
	case "df":
		output.WriteString("Filesystem      Size  Used Avail Use% Mounted on\n")
		output.WriteString("/dev/sda1        80G   35G   42G  46% /\n")
		output.WriteString("/dev/sdb1       200G   78G  112G  41% /data\n")
		output.WriteString("tmpfs           3.9G     0  3.9G   0% /dev/shm\n")
	case "free":
		output.WriteString("              total        used        free      shared  buff/cache   available\n")
		output.WriteString("Mem:        7908352     3421568     1234567       65432     3252217     4256789\n")
		output.WriteString("Swap:       2097148           0     2097148\n")
	case "ps":
		output.WriteString("  PID TTY          TIME CMD\n")
		output.WriteString("    1 ?        00:02:15 systemd\n")
		output.WriteString("  234 ?        00:01:32 nginx\n")
		output.WriteString("  567 ?        00:18:47 java\n")
		output.WriteString("  890 pts/0    00:00:00 bash\n")
		output.WriteString(" 1234 pts/0    00:00:00 ps\n")
	case "uptime":
		output.WriteString(fmt.Sprintf(" %s up 42 days, 3:42,  5 users,  load average: 0.35, 0.48, 0.42\n",
			time.Now().Format("15:04:05")))
	case "hostname":
		output.WriteString(fmt.Sprintf("prod-%s-web01\n", strings.ReplaceAll(host, ".", "-")))
	case "uname":
		output.WriteString("Linux prod-web01 5.14.0-284.el9.x86_64 #1 SMP x86_64 GNU/Linux\n")
	case "systemctl":
		if len(fields) >= 2 && fields[1] == "status" {
			svc := "application"
			if len(fields) >= 3 {
				svc = fields[2]
			}
			output.WriteString(fmt.Sprintf("● %s.service - Web Application Service\n", svc))
			output.WriteString("   Loaded: loaded (/etc/systemd/system/app.service; enabled; vendor preset: disabled)\n")
			output.WriteString("   Active: active (running) since Mon 2026-06-15 08:00:00 CST; 5 days ago\n")
			output.WriteString(" Main PID: 12345 (java)\n")
			output.WriteString("   Tasks: 65 (limit: 4096)\n")
			output.WriteString("   Memory: 1.5G\n")
			output.WriteString("   CGroup: /system.slice/app.service\n")
			output.WriteString("           └─12345 /usr/bin/java -jar /opt/app/app.jar --spring.profiles.active=prod\n")
		} else if len(fields) >= 2 && fields[1] == "restart" {
			svc := "application"
			if len(fields) >= 3 {
				svc = fields[2]
			}
			output.WriteString(fmt.Sprintf("Restarting %s.service...\n", svc))
			time.Sleep(100 * time.Millisecond)
			output.WriteString(fmt.Sprintf("%s.service restarted successfully.\n", svc))
		} else if len(fields) >= 2 && fields[1] == "stop" {
			svc := "application"
			if len(fields) >= 3 {
				svc = fields[2]
			}
			output.WriteString(fmt.Sprintf("Stopping %s.service...\n", svc))
			output.WriteString(fmt.Sprintf("%s.service stopped successfully.\n", svc))
		} else {
			output.WriteString("Usage: systemctl {start|stop|status|restart} <service>\n")
		}
	case "cat", "tail", "head":
		if len(fields) >= 2 {
			file := fields[len(fields)-1]
			output.WriteString(fmt.Sprintf("===== %s =====\n", file))
			output.WriteString("2026-06-20 08:00:01 [INFO] Application started successfully\n")
			output.WriteString("2026-06-20 08:00:05 [INFO] Database connection established\n")
			output.WriteString("2026-06-20 09:05:23 [INFO] Request #10234 processed in 45ms\n")
			output.WriteString("2026-06-20 10:10:45 [WARN] Memory usage: 78%\n")
			output.WriteString("2026-06-20 10:15:00 [INFO] Health check passed\n")
			output.WriteString("2026-06-20 10:30:00 [INFO] Scheduled task executed\n")
			output.WriteString("2026-06-20 11:00:00 [ERROR] Connection timeout to redis (retrying...)\n")
			output.WriteString("2026-06-20 11:00:05 [INFO] Redis connection restored\n")
			output.WriteString("======================================\n")
		} else {
			output.WriteString("Usage: cat <file>\n")
		}
	case "ping":
		target := "localhost"
		if len(fields) >= 2 {
			target = fields[1]
		}
		output.WriteString(fmt.Sprintf("PING %s (127.0.0.1) 56(84) bytes of data.\n", target))
		for i := 1; i <= 4; i++ {
			output.WriteString(fmt.Sprintf("64 bytes from localhost (127.0.0.1): icmp_seq=%d ttl=64 time=0.0%d ms\n", i, i*8+5))
		}
		output.WriteString("\n--- localhost ping statistics ---\n")
		output.WriteString("4 packets transmitted, 4 received, 0% packet loss, time 3002ms\n")
	case "netstat", "ss":
		output.WriteString("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n")
		output.WriteString("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n")
		output.WriteString("tcp        0      0 192.168.1.100:22        10.0.0.5:12345          ESTABLISHED\n")
	case "grep":
		if len(fields) >= 3 {
			pattern := fields[1]
			file := fields[len(fields)-1]
			output.WriteString(fmt.Sprintf("Searching for '%s' in %s:\n", pattern, file))
			output.WriteString("Line 15: 2026-06-20 10:10:45 [WARN] High memory usage detected\n")
			output.WriteString("Line 28: 2026-06-20 11:00:00 [ERROR] Connection timeout\n")
		}
	case "find":
		output.WriteString("./config.yaml\n")
		output.WriteString("./logs/app.log\n")
		output.WriteString("./logs/error.log\n")
		output.WriteString("./bin/start.sh\n")
		output.WriteString("./bin/stop.sh\n")
	case "du":
		output.WriteString("4.0K    ./bin\n")
		output.WriteString("12M     ./logs\n")
		output.WriteString("8.0K    ./etc\n")
		output.WriteString("156M    ./data\n")
		output.WriteString("256M    .\n")
	case "top":
		output.WriteString("top - 11:30:00 up 42 days,  3:42,  5 users,  load average: 0.35, 0.48, 0.42\n")
		output.WriteString("Tasks: 128 total,   1 running, 127 sleeping,   0 stopped,   0 zombie\n")
		output.WriteString("%Cpu(s):  12.5 us,   3.2 sy,  0.0 ni,  83.1 id,   1.2 wa,  0.0 hi,  0.0 si\n")
		output.WriteString("MiB Mem :   7723.0 total,   1234.5 free,   3456.7 used,   3031.8 buff/cache\n")
		output.WriteString("MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   4256.7 avail Mem\n")
		output.WriteString("\n")
		output.WriteString("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
		output.WriteString(" 1234 appuser   20   0  15.2g   1.5g  25672 S  25.3  20.1  18:47.23 java\n")
		output.WriteString("  234 nginx     20   0  18568   3256   2048 S   2.1   0.0   1:32.45 nginx\n")
	default:
		output.WriteString(fmt.Sprintf("[Command executed on %s]\n", host))
		output.WriteString("Operation completed successfully.\n")
	}

	output.WriteString("\n")
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

func GetOperationSessions(c *gin.Context) {
	var sessions []models.OperationSession
	query := database.DB.Preload("OperationRequest").Preload("Operator").Preload("OperationRequest.Requester").Preload("OperationRequest.PrivilegeAccount")

	status := c.Query("status")
	if status != "" {
		query = query.Where("session_status = ?", status)
	}

	opReqID := c.Query("operation_req_id")
	if opReqID != "" {
		id, _ := strconv.Atoi(opReqID)
		query = query.Where("operation_req_id = ?", id)
	}

	operatorID := c.Query("operator_id")
	if operatorID != "" {
		id, _ := strconv.Atoi(operatorID)
		query = query.Where("operator_id = ?", id)
	}

	query = query.Order("created_at DESC")
	query.Find(&sessions)

	c.JSON(http.StatusOK, utils.SuccessResponse(sessions))
}
