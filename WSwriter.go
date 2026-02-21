// ==================== 包声明和导入 ====================
package main

import (
    // 标准库：字节处理
    "bytes"
    // 标准库：上下文管理（用于超时控制）
    "context"
    // 标准库：gzip 压缩
    "compress/gzip"
    // 标准库：AES 加密
    "crypto/aes"
    // 标准库：加密密码模式
    "crypto/cipher"
    // 标准库：HMAC 认证码
    "crypto/hmac"
    // 标准库：随机数生成
    "crypto/rand"
    // 标准库：SHA256 哈希
    "crypto/sha256"
    // 标准库：恒定时间比较（防时序攻击）
    "crypto/subtle"
    // 标准库：TLS 协议
    "crypto/tls"
    // 标准库：Base64 编码
    "encoding/base64"
    // 标准库：CSV 文件处理
    "encoding/csv"
    // 标准库：十六进制编码
    "encoding/hex"
    // 标准库：JSON 解析
    "encoding/json"
    // 标准库：格式化输出
    "fmt"
    // 标准库：HTML 转义
    "html"
    // 标准库：文件 I/O
    "io"
    // 标准库：日志记录
    "log"
    // 标准库：网络相关
    "net"
    // 标准库：邮箱解析
    "net/mail"
    // 标准库：HTTP 协议
    "net/http"
    // 标准库：SMTP 邮件发送
    "net/smtp"
    // 标准库：URL 编码
    "net/url"
    // 标准库：操作系统接口
    "os"
    // 标准库：执行外部命令
    "os/exec"
    // 标准库：路径操作
    "path/filepath"
    // 标准库：正则表达式
    "regexp"
    // 标准库：运行时信息
    "runtime"
    // 标准库：排序
    "sort"
    // 标准库：字符串处理
    "strconv"
    // 标准库：字符串操作
    "strings"
    // 标准库：同步原语（互斥锁等）
    "sync"
    // 标准库：时间处理
    "time"
)

// ==================== 常量定义 ====================

const (
    // HTTP 服务器监听端口
    PORT     = 8080
    // Hugo 预览服务器端口
    htmlPort = 1313
)

// ==================== 全局变量 ====================

var hugoPath string // Hugo 项目根目录路径

const (
    // 评论字段长度限制，防止滥用
    maxCommentNameLen   = 50    // 评论作者名称最大长度
    maxCommentEmailLen  = 100   // 评论邮箱最大长度
    maxCommentContentLen = 2000 // 评论内容最大长度
    maxCommentImages    = 5     // 每个评论最多上传图片数
    maxImageSize        = 5 << 20 // 单张图片最大 5MB
)

var (
    // 从环境变量读取的管理员令牌
    adminToken = ""
    // 限流记录：存储每个 IP/用户的请求时间戳
    // 用于实现基于时间窗口的请求限流
    rateLimiter = struct {
        sync.Mutex
        records map[string][]time.Time // key: "操作:IP", value: 请求时间戳列表
    }{records: make(map[string][]time.Time)}
)

// ==================== 数据结构定义 ====================

// Post 代表一篇博客文章的元数据
type Post struct {
    Title       string `json:"title"`       // 文章标题
    Lang        string `json:"lang"`        // 语言代码 (zh-cn 或 en)
    Path        string `json:"path"`        // 文章文件路径
    Date        string `json:"date"`        // 发布日期
    Status      string `json:"status"`      // 文章状态 (PUBLISHED/DRAFT/UNSAVED)
    StatusColor string `json:"status_color"` // 状态颜色代码
    Pinned      bool   `json:"pinned"`      // 是否置顶
}

// Frontmatter 代表 Markdown 文件的 YAML 前言元数据
type Frontmatter struct {
    Title      string   // 文章标题
    Draft      bool     // 是否为草稿
    Date       string   // 发布日期
    Categories []string // 文章分类
    Pinned     bool     // 是否置顶
}

// APIResponse 是所有 API 响应的通用格式
type APIResponse struct {
    Success bool        `json:"success"`           // 操作是否成功
    Message string      `json:"message,omitempty"` // 响应消息
    Content string      `json:"content,omitempty"` // 响应内容
    Data    interface{} `json:"data,omitempty"`    // 响应数据
}

// Comment 代表一条评论
type Comment struct {
    ID           string   `json:"id"`             // 评论唯一 ID (时间戳-序号)
    Author       string   `json:"author"`         // 评论者名称
    Email        string   `json:"email"`          // 评论者邮箱
    Content      string   `json:"content"`        // 评论内容
    Timestamp    string   `json:"timestamp"`      // 评论时间戳
    Approved     bool     `json:"approved"`       // 是否已批准
    PostPath     string   `json:"post_path"`      // 评论所在文章路径
    IPAddress    string   `json:"ip_address"`     // 评论者 IP 地址（安全记录）
    UserAgent    string   `json:"user_agent"`     // 评论者浏览器 User-Agent
    ParentID     string   `json:"parent_id,omitempty"` // 父评论 ID（支持嵌套回复）
    Images       []string `json:"images,omitempty"`    // 评论中上传的图片 URL
    IssueNumber  int      `json:"issue_number,omitempty"` // GitHub Issue 编号（用于删除）
}

// CommentSettings 代表评论系统的配置settings
type CommentSettings struct {
    SMTPEnabled     bool     `json:"smtp_enabled"`      // 是否启用 SMTP 邮件通知
    SMTPHost        string   `json:"smtp_host"`         // SMTP 服务器地址
    SMTPPort        int      `json:"smtp_port"`         // SMTP 端口
    SMTPUser        string   `json:"smtp_user"`         // SMTP 用户名
    SMTPPass        string   `json:"smtp_pass"`         // SMTP 密码（可加密存储）
    SMTPFrom        string   `json:"smtp_from"`         // 发件人地址
    SMTPTo          []string `json:"smtp_to"`           // 收件人列表
    NotifyOnPending bool     `json:"notify_on_pending"` // 新评论时是否发送邮件通知
    BlacklistIPs    []string `json:"blacklist_ips"`     // IP 黑名单
    BlacklistWords  []string `json:"blacklist_keywords"`// 关键词黑名单
}

// CommentsFile 代表 comments.json 文件的结构
type CommentsFile struct {
    Comments []Comment `json:"comments"` // 评论数组
}

// ==================== 密码加密管理函数 ====================

// getSMTPEncryptionKey 从环境变量获取用于加密 SMTP 密码的密钥
// 必须是 64 个十六进制字符（32 字节用于 AES-256）
func getSMTPEncryptionKey() ([]byte, error) {
    keyHex := os.Getenv("SMTP_ENCRYPTION_KEY")
    if keyHex == "" {
        return nil, fmt.Errorf("SMTP_ENCRYPTION_KEY not set in environment")
    }
    
    key, err := hex.DecodeString(keyHex)
    if err != nil {
        return nil, fmt.Errorf("invalid SMTP_ENCRYPTION_KEY format: %v", err)
    }
    
    if len(key) != 32 {
        return nil, fmt.Errorf("SMTP_ENCRYPTION_KEY must be 64 hex characters (32 bytes for AES-256)")
    }
    
    return key, nil
}

// ==================== JWT 身份认证系统 ====================

var jwtSecret []byte // JWT 签名密钥

// initJWTSecret 初始化 JWT 密钥
// 优先级：环境变量 > 文件 > 生成新密钥
func initJWTSecret() {
    // 优先从环境变量读取
    secretEnv := os.Getenv("JWT_SECRET")
    if secretEnv != "" {
        jwtSecret = []byte(secretEnv)
        return
    }
    
    // 从本地文件读取（用于持久化）
    secretFile := filepath.Join(hugoPath, "config", ".jwt_secret")
    if secret, err := os.ReadFile(secretFile); err == nil {
        jwtSecret = secret
        return
    }
    
    // 生成新的 32 字节随机密钥
    newSecret := make([]byte, 32)
    if _, err := rand.Read(newSecret); err != nil {
        log.Fatalf("[FATAL] 无法生成JWT密钥，请设置JWT_SECRET环境变量: %v", err)
        return
    }
    
    jwtSecret = newSecret
    
    // 尝试保存到文件（用于重启后使用相同密钥）
    secretFile = filepath.Join(hugoPath, "config", ".jwt_secret")
    if err := os.WriteFile(secretFile, newSecret, 0600); err != nil {
        log.Printf("[WARN] Failed to save JWT secret: %v", err)
    }
}

// jwtClaims 代表 JWT token 中的声明信息
type jwtClaims struct {
    Sub string `json:"sub"` // 用户标识符 (Subject)
    Iat int64  `json:"iat"` // 签发时间 (Issued At)
    Exp int64  `json:"exp"` // 过期时间 (Expiration Time)
    Jti string `json:"jti"` // JWT ID，用于令牌轮转和撤销
    Typ string `json:"typ"` // 令牌类型："access" 或 "refresh"
}

// 刷新令牌存储 (内存存储，生产环境建议使用 Redis)
var refreshTokenStore = make(map[string]int64) // jti -> 过期时间戳
var refreshTokenMutex sync.RWMutex

// ==================== 初始化和启动 ====================

func init() {
    var err error
    // 获取当前工作目录作为 Hugo 项目根路径
    hugoPath, err = os.Getwd()
    if err != nil {
        panic(err)
    }
    
    // 初始化 JWT 密钥
    initJWTSecret()
    // 从环境变量加载管理员令牌
    adminToken = os.Getenv("ADMIN_TOKEN")
}

func main() {
    // 加载 .env 文件中的环境变量
    loadEnvFile(".env")
    
    // ... 服务器启动逻辑 ...
}
