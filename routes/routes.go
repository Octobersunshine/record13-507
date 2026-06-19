package routes

import (
	"privilege-vault/controllers"
	"privilege-vault/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	r.Use(middleware.CORSMiddleware())
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	api := r.Group("/api/v1")
	{
		api.POST("/auth/login", controllers.Login)

		auth := api.Group("")
		auth.Use(middleware.JWTAuth())
		auth.Use(middleware.AuditLogger())
		{
			auth.GET("/auth/me", controllers.GetCurrentUser)
			auth.PUT("/auth/change-password", controllers.ChangePassword)

			admin := auth.Group("/admin")
			admin.Use(middleware.RoleAuth("super_admin"))
			{
				admin.GET("/users", controllers.ListUsers)
				admin.GET("/users/:id", controllers.GetUser)
				admin.POST("/users", controllers.CreateUser)
				admin.PUT("/users/:id", controllers.UpdateUser)
				admin.DELETE("/users/:id", controllers.DeleteUser)
			}

			accounts := auth.Group("/accounts")
			{
				accounts.GET("", controllers.ListPrivilegeAccounts)
				accounts.GET("/:id", controllers.GetPrivilegeAccount)

				accountAdmin := accounts.Group("")
				accountAdmin.Use(middleware.RoleAuth("super_admin", "reviewer"))
				{
					accountAdmin.POST("", controllers.CreatePrivilegeAccount)
					accountAdmin.PUT("/:id", controllers.UpdatePrivilegeAccount)
					accountAdmin.DELETE("/:id", controllers.DeletePrivilegeAccount)
					accountAdmin.POST("/:id/test-connection", controllers.TestAccountConnection)
				}
			}

			operations := auth.Group("/operations")
			{
				operations.GET("", controllers.ListOperationRequests)
				operations.GET("/my", controllers.ListMyOperations)
				operations.GET("/:id", controllers.GetOperationRequest)
				operations.POST("", controllers.CreateOperationRequest)
				operations.POST("/:id/cancel", controllers.CancelOperationRequest)
			}

			reviews := auth.Group("/reviews")
			reviews.Use(middleware.RoleAuth("super_admin", "reviewer"))
			{
				reviews.GET("/pending", controllers.GetMyPendingReviews)
				reviews.POST("/operations/:id/review", controllers.ReviewOperationRequest)
			}

			execution := auth.Group("/execution")
			{
				execution.POST("/operations/:id", controllers.ExecuteOperation)
				execution.POST("/sessions/:session_id/execute", controllers.ExecuteCommandInSession)
				execution.POST("/sessions/:session_id/close", controllers.CloseOperationSession)
				execution.GET("/sessions/:session_id", controllers.GetOperationSession)
				execution.GET("/sessions", controllers.GetOperationSessions)
			}

			audit := auth.Group("/audit")
			audit.Use(middleware.RoleAuth("super_admin", "reviewer"))
			{
				audit.GET("/logs", controllers.ListAuditLogs)
				audit.GET("/logs/:id", controllers.GetAuditLog)
				audit.GET("/statistics", controllers.GetAuditStatistics)
			}

			stats := auth.Group("/statistics")
			{
				stats.GET("/overview", controllers.GetAuditStatistics)
			}
		}
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "Privilege Vault API",
			"version": "1.0.0",
		})
	})
}
