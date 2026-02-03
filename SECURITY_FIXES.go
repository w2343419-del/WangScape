// SECURITY_FIXES.go - 安全修复建议代码
// 此文件包含针对WSwriter.go中发现的安全漏洞的修复建议

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// =====================================================
// 修复 #1: SMTP密码加密存储
// =====================================================

// EncryptedCommentSettings 添加加密的SMTP密码存储
type EncryptedCommentSettings struct {
	SMTPEnabled          bool     `json:"smtp_enabled"`
	SMTPHost             string   `json:"smtp_host"`
	SMTPPort             int      `json:"smtp_port"`
	SMTPUser             string   `json:"smtp_user"`
	SMTPPassEncrypted    string   `json:"smtp_pass_encrypted"` // 加密存储，不要SMTPPass
	SMTPPassIV           string   `json:"smtp_pass_iv"`        // IV值
	SMTPFrom             string   `json:"smtp_from"`
	SMTPTo               []string `json:"smtp_to"`
	NotifyOnPending      bool     `json:"notify_on_pending"`
	BlacklistIPs         []string `json:"blacklist_ips"`
	BlacklistWords       []string `json:"blacklist_keywords"`
	// 新增：加密密钥应从环境变量或密钥管理系统读取，绝不存储在配置文件中
}

// SMTPEncryption 使用AES-256-GCM加密SMTP密码
type SMTPEncryption struct {
	key []byte
}

// NewSMTPEncryption 创建加密器，密钥应从环境变量获取
func NewSMTPEncryption(keyHex string) (*SMTPEncryption, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("encryption key not configured")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256")
	}
	return &SMTPEncryption{key: key}, nil
}

// EncryptPassword 加密SMTP密码
func (se *SMTPEncryption) EncryptPassword(password string) (encrypted, iv string, err error) {
	block, err := aes.NewCipher(se.key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	encrypted = base64.StdEncoding.EncodeToString(ciphertext)
	iv = hex.EncodeToString(nonce)
	return
}

// DecryptPassword 解密SMTP密码
func (se *SMTPEncryption) DecryptPassword(encrypted, iv string) (string, error) {
	block, err := aes.NewCipher(se.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	nonce, err := hex.DecodeString(iv)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// =====================================================
// 修复 #2: HTML转义防XSS
// =====================================================

// HTMLEscape 函数集，用于安全处理用户输入
type HTMLSanitizer struct{}

// EscapeComment 安全转义评论数据
func (hs *HTMLSanitizer) EscapeComment(comment Comment) Comment {
	return Comment{
		ID:        comment.ID, // ID由系统生成，不需转义
		Author:    html.EscapeString(comment.Author),
		Email:     html.EscapeString(comment.Email),
		Content:   html.EscapeString(comment.Content),
		Timestamp: comment.Timestamp, // 时间戳，不需转义
		Approved:  comment.Approved,
		PostPath:  comment.PostPath, // 路径由系统控制，不需转义
		IPAddress: comment.IPAddress, // IP不需转义
		UserAgent: html.EscapeString(comment.UserAgent),
		ParentID:  comment.ParentID,
		Images:    comment.Images, // 图片路径由系统控制
	}
}

// JavaScriptEscape 用于安全的JavaScript字符串
func (hs *HTMLSanitizer) JavaScriptEscape(s string) string {
	replacements := map[string]string{
		"\\": "\\\\",
		"'":  "\\'",
		"\"": "\\\"",
		"\n": "\\n",
		"\r": "\\r",
		"</": "<\\/",
	}
	result := s
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}
	return result
}

// =====================================================
// 修复 #3: 完善路径遍历防护
// =====================================================

// PathValidator 严格的路径验证
type PathValidator struct {
	basePath string
	allowed  map[string]bool // 允许的目录白名单
}

// NewPathValidator 创建路径验证器
func NewPathValidator(basePath string, allowedDirs []string) (*PathValidator, error) {
	// 规范化基础路径
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return nil, err
	}

	allowed := make(map[string]bool)
	for _, dir := range allowedDirs {
		absDir, _ := filepath.Abs(filepath.Join(absBase, dir))
		allowed[strings.ToLower(absDir)] = true
	}

	return &PathValidator{
		basePath: strings.ToLower(absBase),
		allowed:  allowed,
	}, nil
}

// ValidateFilePath 严格验证文件路径
func (pv *PathValidator) ValidateFilePath(relPath string, expectedExtensions ...string) (string, error) {
	// 1. 检查空路径
	if relPath == "" {
		return "", fmt.Errorf("path cannot be empty")
	}

	// 2. 规范化路径 - 多次Clean确保安全
	cleaned := filepath.Clean(relPath)
	cleaned = filepath.Clean(cleaned) // Double clean to be safe

	// 3. 检查绝对路径和目录遍历
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths not allowed")
	}

	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") || strings.Contains(cleaned, "/..\\") {
		return "", fmt.Errorf("directory traversal not allowed")
	}

	// 4. Windows特定检查
	if strings.ContainsAny(cleaned, ":") {
		return "", fmt.Errorf("invalid characters in path")
	}

	// 5. 构建完整路径
	fullPath := filepath.Join(pv.basePath, cleaned)
	fullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}

	// 6. 验证最终路径在基目录内
	fullPath = strings.ToLower(fullPath)
	if !strings.HasPrefix(fullPath, pv.basePath) {
		return "", fmt.Errorf("path outside base directory")
	}

	// 7. 验证文件扩展名白名单
	if len(expectedExtensions) > 0 {
		ext := strings.ToLower(filepath.Ext(fullPath))
		allowed := false
		for _, allowedExt := range expectedExtensions {
			if ext == allowedExt {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("file extension not allowed")
		}
	}

	// 8. 验证目录白名单（如果配置）
	if len(pv.allowed) > 0 {
		dir := filepath.Dir(fullPath)
		if !pv.allowed[dir] && !strings.HasPrefix(dir, pv.basePath+string(filepath.Separator)+"allowed") {
			// 检查是否在允许的目录树中
			allowed := false
			for allowedDir := range pv.allowed {
				if strings.HasPrefix(dir, allowedDir) {
					allowed = true
					break
				}
			}
			if !allowed {
				return "", fmt.Errorf("directory not in whitelist")
			}
		}
	}

	return fullPath, nil
}

// =====================================================
// 修复 #4: 输入验证加强
// =====================================================

// InputValidator 严格的输入验证
type InputValidator struct {
	maxNameLen    int
	maxEmailLen   int
	maxContentLen int
	maxImages     int
}

// ValidateComment 验证评论输入
func (iv *InputValidator) ValidateComment(author, email, content string, imageCount int) error {
	// 1. 长度检查
	if author == "" || len(author) > iv.maxNameLen {
		return fmt.Errorf("author name length must be 1-%d characters", iv.maxNameLen)
	}

	if len(email) > iv.maxEmailLen {
		return fmt.Errorf("email length must not exceed %d characters", iv.maxEmailLen)
	}

	if content == "" || len(content) > iv.maxContentLen {
		return fmt.Errorf("content length must be 1-%d characters", iv.maxContentLen)
	}

	if imageCount > iv.maxImages {
		return fmt.Errorf("maximum %d images allowed", iv.maxImages)
	}

	// 2. 邮箱格式验证
	if !isValidEmail(email) {
		return fmt.Errorf("invalid email format")
	}

	// 3. 内容检查 - 防止全空白
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("content cannot be empty")
	}

	return nil
}

// isValidEmail 简单邮箱验证
func isValidEmail(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

// =====================================================
// 修复 #5: 改进IP检查 - 防范代理欺骗
// =====================================================

// IPValidator 可靠的IP提取
type IPValidator struct {
	trustedProxies map[string]bool // 信任的代理IP
}

// GetRealIP 从请求中安全地获取客户端IP
func (ipv *IPValidator) GetRealIP(r *http.Request) string {
	// 1. 仅当来自信任的代理时才使用X-Forwarded-For
	remoteIP := strings.Split(r.RemoteAddr, ":")[0]
	
	if ipv.trustedProxies[remoteIP] {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}

	// 2. 优先使用X-Real-IP（如果来自信任的代理）
	if ipv.trustedProxies[remoteIP] {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// 3. 默认使用RemoteAddr
	return remoteIP
}

// =====================================================
// 修复 #6: 命令执行安全
// =====================================================

// CommandExecutor 安全的命令执行
type CommandExecutor struct {
	timeout      time.Duration
	allowedCmds  map[string]bool
	workingDir   string
}

// NewCommandExecutor 创建命令执行器
func NewCommandExecutor(workingDir string, timeout time.Duration) *CommandExecutor {
	return &CommandExecutor{
		timeout:     timeout,
		workingDir:  workingDir,
		allowedCmds: map[string]bool{"preview": true, "deploy": true, "build": true, "sync": true},
	}
}

// IsCommandAllowed 检查命令是否在白名单中
func (ce *CommandExecutor) IsCommandAllowed(cmd string) bool {
	return ce.allowedCmds[cmd]
}

// 建议：所有exec.Command调用都应添加超时和环境隔离

// =====================================================
// 修复 #7: 增强的CORS检查
// =====================================================

// CORSValidator CORS验证
type CORSValidator struct {
	allowedOrigins map[string]bool
}

// IsOriginAllowed 安全的CORS origin检查
func (cv *CORSValidator) IsOriginAllowed(origin string) bool {
	// 1. 规范化URL
	if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
		return false
	}

	// 2. 检查白名单
	return cv.allowedOrigins[origin]
}

// =====================================================
// 修复 #8: 文件权限安全
// =====================================================

// FilePermissionHelper 文件权限安全管理
type FilePermissionHelper struct{}

// SetSensitiveFilePermissions 为敏感文件设置严格权限
func (fph *FilePermissionHelper) SetSensitiveFilePermissions(filePath string) error {
	// 0600 = 只有所有者可读写，没有其他权限
	return os.Chmod(filePath, 0600)
}

// SetNormalFilePermissions 为普通文件设置权限
func (fph *FilePermissionHelper) SetNormalFilePermissions(filePath string) error {
	// 0644 = 所有者可读写，其他用户只读
	return os.Chmod(filePath, 0644)
}

// =====================================================
// 修复 #9: 审计日志
// =====================================================

// AuditLog 审计日志记录
type AuditLog struct {
	Timestamp  string // RFC3339格式
	Action     string // 操作类型
	UserIP     string // 用户IP
	UserAgent  string // User-Agent
	ResourceID string // 资源ID（如PostPath、CommentID）
	Result     string // success/failure
	Details    string // 详细信息
}

// LogAuditEvent 记录审计事件
func LogAuditEvent(action, userIP, userAgent, resourceID, result, details string) {
	event := AuditLog{
		Timestamp:  time.Now().Format(time.RFC3339),
		Action:     action,
		UserIP:     userIP,
		UserAgent:  userAgent,
		ResourceID: resourceID,
		Result:     result,
		Details:    details,
	}
	// TODO: 将事件写入结构化日志（JSON）
	// 建议使用logrus或zap库
	fmt.Printf("[AUDIT] %+v\n", event)
}

// =====================================================
// 使用示例和建议
// =====================================================

/*

在main()中的初始化部分：

func main() {
	// 1. 初始化加密器
	encryptor, err := NewSMTPEncryption(os.Getenv("SMTP_ENCRYPTION_KEY"))
	if err != nil {
		log.Fatal("Failed to initialize SMTP encryption:", err)
	}

	// 2. 初始化路径验证器
	pathValidator, err := NewPathValidator(
		hugoPath,
		[]string{"content", "static/img/comments"},
	)
	if err != nil {
		log.Fatal("Failed to initialize path validator:", err)
	}

	// 3. 初始化输入验证器
	inputValidator := &InputValidator{
		maxNameLen:    50,
		maxEmailLen:   100,
		maxContentLen: 2000,
		maxImages:     5,
	}

	// 4. 初始化IP验证器
	ipValidator := &IPValidator{
		trustedProxies: map[string]bool{
			"127.0.0.1": true,
			"::1": true,
		},
	}

	// 5. 初始化CORS验证器
	corsValidator := &CORSValidator{
		allowedOrigins: map[string]bool{
			"http://localhost:1313": true,
			"http://127.0.0.1:1313": true,
			"http://localhost:8080": true,
			"http://127.0.0.1:8080": true,
		},
	}

	// 6. 设置路由...
	// 所有路由都应使用上述验证器进行输入验证
}

*/

// =====================================================
// SMTP安全连接建议
// =====================================================

/*

当前代码使用:
	auth := smtp.PlainAuth("", settings.SMTPUser, settings.SMTPPass, settings.SMTPHost)
	return smtp.SendMail(addr, auth, from, settings.SMTPTo, msg.Bytes())

安全修复建议:

// Option 1: 使用SMTPS (端口465)
func sendEmailSMTPS(host string, port int, user, pass string, from string, to []string, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConfig := &tls.Config{
		ServerName: host,
		InsecureSkipVerify: false, // 在生产环境中必须验证证书
	}
	
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	
	auth := smtp.PlainAuth("", user, pass, host)
	if err := client.Auth(auth); err != nil {
		return err
	}
	
	return client.SendMail(from, to, msg)
}

// Option 2: 使用SMTP + STARTTLS (端口587)
func sendEmailSTARTTLS(host string, port int, user, pass string, from string, to []string, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()
	
	// 升级到TLS
	tlsConfig := &tls.Config{
		ServerName: host,
		InsecureSkipVerify: false,
	}
	
	if err := client.StartTLS(tlsConfig); err != nil {
		return err
	}
	
	auth := smtp.PlainAuth("", user, pass, host)
	if err := client.Auth(auth); err != nil {
		return err
	}
	
	if err := client.Mail(from); err != nil {
		return err
	}
	
	for _, addr := range to {
		if err := client.Rcpt(addr); err != nil {
			return err
		}
	}
	
	w, err := client.Data()
	if err != nil {
		return err
	}
	
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	
	return w.Close()
}

*/

// 导入包提醒
/*
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/http"
	"net/smtp"
	// ... 其他导入
)
*/

// =====================================================
// 弃用警告
// =====================================================

/*
需要将以下导入/函数替换为现代版本：

1. ioutil.ReadFile() -> os.ReadFile() (Go 1.16+)
   ioutil.WriteFile() -> os.WriteFile() (Go 1.16+)
   ioutil.TempDir() -> os.MkdirTemp() (Go 1.16+)
   ioutil.TempFile() -> os.CreateTemp() (Go 1.16+)
   ioutil.ReadAll() -> io.ReadAll() (Go 1.16+)
   ioutil.ReadDir() -> os.ReadDir() (Go 1.16+) - 返回DirEntry而不是FileInfo
   ioutil.NopCloser() -> io.NopCloser() (始终可用)

*/
