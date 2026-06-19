package models

import (
	"time"
)

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"size:50;uniqueIndex;not null" json:"username"`
	Password  string    `gorm:"size:255;not null" json:"-"`
	RealName  string    `gorm:"size:50" json:"real_name"`
	Role      string    `gorm:"size:20;not null" json:"role"`
	Email     string    `gorm:"size:100" json:"email"`
	Phone     string    `gorm:"size:20" json:"phone"`
	Status    int       `gorm:"default:1" json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PrivilegeAccount struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	AccountName     string    `gorm:"size:100;not null" json:"account_name"`
	SystemName      string    `gorm:"size:100;not null" json:"system_name"`
	SystemType      string    `gorm:"size:50;not null" json:"system_type"`
	Host            string    `gorm:"size:255" json:"host"`
	Port            int       `gorm:"default:22" json:"port"`
	Username        string    `gorm:"size:100;not null" json:"username"`
	EncryptedPass   string    `gorm:"type:text;not null" json:"-"`
	Description     string    `gorm:"size:500" json:"description"`
	OwnerID         uint      `gorm:"not null" json:"owner_id"`
	Owner           *User     `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	AllowedUserIDs  string    `gorm:"type:text" json:"-"`
	NeedReview      bool      `gorm:"default:true" json:"need_review"`
	Status          int       `gorm:"default:1" json:"status"`
	LastPasswordAt  *time.Time `json:"last_password_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type OperationRequest struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	RequestNo         string    `gorm:"size:50;uniqueIndex" json:"request_no"`
	RequesterID       uint      `gorm:"not null" json:"requester_id"`
	Requester         *User     `gorm:"foreignKey:RequesterID" json:"requester,omitempty"`
	PrivilegeAccID    uint      `gorm:"not null" json:"privilege_acc_id"`
	PrivilegeAccount  *PrivilegeAccount `gorm:"foreignKey:PrivilegeAccID" json:"privilege_account,omitempty"`
	OperationType     string    `gorm:"size:50;not null" json:"operation_type"`
	OperationCommand  string    `gorm:"type:text;not null" json:"operation_command"`
	Reason            string    `gorm:"size:500;not null" json:"reason"`
	ExpectedStartTime *time.Time `json:"expected_start_time"`
	ExpectedEndTime   *time.Time `json:"expected_end_time"`
	Status            string    `gorm:"size:20;default:pending" json:"status"`
	ReviewerID        *uint     `json:"reviewer_id"`
	Reviewer          *User     `gorm:"foreignKey:ReviewerID" json:"reviewer,omitempty"`
	ReviewComment     string    `gorm:"size:500" json:"review_comment"`
	ReviewedAt        *time.Time `json:"reviewed_at"`
	ExecutedAt        *time.Time `json:"executed_at"`
	ExecResult        string    `gorm:"type:text" json:"exec_result"`
	ExecStatus        string    `gorm:"size:20" json:"exec_status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	UserID      uint      `gorm:"not null" json:"user_id"`
	User        *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Username    string    `gorm:"size:50" json:"username"`
	Action      string    `gorm:"size:100;not null" json:"action"`
	Resource    string    `gorm:"size:100" json:"resource"`
	ResourceID  uint      `json:"resource_id"`
	Detail      string    `gorm:"type:text" json:"detail"`
	IPAddress   string    `gorm:"size:50" json:"ip_address"`
	UserAgent   string    `gorm:"size:500" json:"user_agent"`
	Result      int       `gorm:"default:1" json:"result"`
	CreatedAt   time.Time `json:"created_at"`
}

type OperationSession struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	SessionID        string    `gorm:"size:100;uniqueIndex" json:"session_id"`
	OperationReqID   uint      `gorm:"not null" json:"operation_req_id"`
	OperationRequest *OperationRequest `gorm:"foreignKey:OperationReqID" json:"operation_request,omitempty"`
	StartTime        time.Time `json:"start_time"`
	EndTime          *time.Time `json:"end_time"`
	SessionStatus    string    `gorm:"size:20;default:active" json:"session_status"`
	CommandCount     int       `gorm:"default:0" json:"command_count"`
	SessionLog       string    `gorm:"type:text" json:"session_log"`
	CreatedAt        time.Time `json:"created_at"`
}
