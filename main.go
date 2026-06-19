package main

import (
	"fmt"
	"log"
	"privilege-vault/config"
	"privilege-vault/database"
	"privilege-vault/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("   特权账号密码托管系统 - Privilege Vault")
	fmt.Println("========================================")
	fmt.Println()

	config.LoadConfig()
	fmt.Println("[OK] 配置加载完成")

	if err := database.InitDB(); err != nil {
		log.Fatalf("[FAIL] 数据库初始化失败: %v", err)
	}
	fmt.Println("[OK] 数据库初始化完成 (SQLite)")

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	routes.SetupRoutes(r)
	fmt.Println("[OK] 路由注册完成")

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("服务启动信息:")
	fmt.Println("  监听地址: http://localhost" + config.AppConfig.ServerPort)
	fmt.Println("  API路径:  /api/v1")
	fmt.Println()
	fmt.Println("默认账号 (初始密码均为 admin123):")
	fmt.Println("  超级管理员: admin / admin123")
	fmt.Println("  运维人员:   ops001 / admin123")
	fmt.Println("  审批人:     reviewer01 / admin123")
	fmt.Println("========================================")
	fmt.Println()

	if err := r.Run(config.AppConfig.ServerPort); err != nil {
		log.Fatalf("[FAIL] 服务启动失败: %v", err)
	}
}
