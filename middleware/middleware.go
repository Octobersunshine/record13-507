package middleware

import (
	"net/http"
	"privilege-vault/database"
	"privilege-vault/models"
	"privilege-vault/utils"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	UsernameKey contextKey = "username"
	RoleKey     contextKey = "role"
)

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(401, "未提供认证令牌"))
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(401, "认证令牌格式错误"))
			c.Abort()
			return
		}

		claims, err := utils.ParseToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, utils.ErrorResponse(401, "认证令牌无效或已过期"))
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func RoleAuth(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "未找到用户角色信息"))
			c.Abort()
			return
		}

		userRole := role.(string)
		for _, allowed := range allowedRoles {
			if userRole == allowed {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, utils.ErrorResponse(403, "权限不足，无法执行此操作"))
		c.Abort()
	}
}

func AuditLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")
		ip := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		action := c.Request.Method + " " + c.FullPath()

		c.Next()

		statusCode := c.Writer.Status()
		result := 1
		if statusCode >= 400 {
			result = 0
		}

		var uid uint
		if userID != nil {
			uid = userID.(uint)
		}

		var uname string
		if username != nil {
			uname = username.(string)
		}

		log := models.AuditLog{
			UserID:    uid,
			Username:  uname,
			Action:    action,
			Resource:  c.Param("id"),
			Detail:    c.Request.URL.RawQuery,
			IPAddress: ip,
			UserAgent: userAgent,
			Result:    result,
			CreatedAt: time.Now(),
		}
		database.DB.Create(&log)
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
