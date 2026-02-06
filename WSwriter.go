package main

import (
    "bytes"
    "context"
    "compress/gzip"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "crypto/tls"
    "encoding/base64"
    "encoding/csv"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "html"
    "io"
    "log"
    "net"
    "net/mail"
    "net/http"
    "net/smtp"
    "net/url"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
)

const (
	PORT     = 8080
	htmlPort = 1313
)

var hugoPath string

const (
    maxCommentNameLen   = 50
    maxCommentEmailLen  = 100
    maxCommentContentLen = 2000
    maxCommentImages    = 5
    maxImageSize        = 5 << 20
)

var (
    adminToken = "" // 从环境变量或配置读取
    rateLimiter = struct {
        sync.Mutex
        records map[string][]time.Time
    }{records: make(map[string][]time.Time)}
)

// Post represents a blog post
type Post struct {
	Title       string `json:"title"`
	Lang        string `json:"lang"`
	Path        string `json:"path"`
	Date        string `json:"date"`
	Status      string `json:"status"`
	StatusColor string `json:"status_color"`
	Pinned      bool   `json:"pinned"`
}

// Frontmatter represents post metadata
type Frontmatter struct {
	Title      string
	Draft      bool
	Date       string
	Categories []string
	Pinned     bool
}

// APIResponse is a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Content string      `json:"content,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Comment represents a blog comment
type Comment struct {
	ID           string   `json:"id"`
	Author       string   `json:"author"`
	Email        string   `json:"email"`
	Content      string   `json:"content"`
	Timestamp    string   `json:"timestamp"`
	Approved     bool     `json:"approved"`
	PostPath     string   `json:"post_path"`
	IPAddress    string   `json:"ip_address"`
	UserAgent    string   `json:"user_agent"`
    ParentID     string   `json:"parent_id,omitempty"`
    Images       []string `json:"images,omitempty"`
    IssueNumber  int      `json:"issue_number,omitempty"` // GitHub Issue编号，用于删除
}

// CommentSettings represents comment notification and blacklist settings
type CommentSettings struct {
    SMTPEnabled     bool     `json:"smtp_enabled"`
    SMTPHost        string   `json:"smtp_host"`
    SMTPPort        int      `json:"smtp_port"`
    SMTPUser        string   `json:"smtp_user"`
    SMTPPass        string   `json:"smtp_pass"`
    SMTPFrom        string   `json:"smtp_from"`
    SMTPTo          []string `json:"smtp_to"`
    NotifyOnPending bool     `json:"notify_on_pending"`
    BlacklistIPs    []string `json:"blacklist_ips"`
    BlacklistWords  []string `json:"blacklist_keywords"`
}

// CommentsFile represents the comments data file structure
type CommentsFile struct {
	Comments []Comment `json:"comments"`
}


func getCommentSettingsPath() string {
    return filepath.Join(hugoPath, "config", "comment_settings.json")
}


func loadCommentSettings() CommentSettings {
    path := getCommentSettingsPath()
    settings := CommentSettings{
        SMTPEnabled:     false,
        SMTPPort:        587,
        SMTPTo:          []string{"w2343419@gmail.com"},
        NotifyOnPending: true,
        BlacklistIPs:    []string{},
        BlacklistWords:  []string{},
    }

    if _, err := os.Stat(path); os.IsNotExist(err) {
        return settings
    }

    content, err := os.ReadFile(path)
    if err != nil {
        return settings
    }

    if err := json.Unmarshal(content, &settings); err != nil {
        return settings
    }

    return settings
}

func saveCommentSettings(settings CommentSettings) error {
    path := getCommentSettingsPath()
    data, err := json.MarshalIndent(settings, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}


func isCommentBlacklisted(settings CommentSettings, ip, author, email, content string) bool {
    ip = strings.TrimSpace(strings.ToLower(ip))
    text := strings.ToLower(strings.Join([]string{author, email, content}, " "))

    for _, b := range settings.BlacklistIPs {
        if strings.TrimSpace(strings.ToLower(b)) != "" && ip != "" && strings.Contains(ip, strings.TrimSpace(strings.ToLower(b))) {
            return true
        }
    }

    for _, w := range settings.BlacklistWords {
        keyword := strings.TrimSpace(strings.ToLower(w))
        if keyword != "" && strings.Contains(text, keyword) {
            return true
        }
    }

    return false
}

func sendCommentNotification(settings CommentSettings, comment Comment, postTitle string) error {
    if !settings.SMTPEnabled {
        log.Printf("[DEBUG] SMTP未启用，跳过邮件发送")
        return nil
    }
    if !settings.NotifyOnPending {
        log.Printf("[DEBUG] 通知功能未启用，跳过邮件发送")
        return nil
    }
    
    log.Printf("[DEBUG] 准备发送邮件: 主机=%s 端口=%d 用户=%s 收件人=%v", settings.SMTPHost, settings.SMTPPort, settings.SMTPUser, settings.SMTPTo)

    from := settings.SMTPFrom
    if from == "" {
        from = settings.SMTPUser
    }
    if from == "" || len(settings.SMTPTo) == 0 || settings.SMTPHost == "" || settings.SMTPPort == 0 {
        log.Printf("[WARN] SMTP配置不完整: from=%s to=%v host=%s port=%d", from, settings.SMTPTo, settings.SMTPHost, settings.SMTPPort)
        return nil
    }

    subject := fmt.Sprintf("新评论待审核 - %s", postTitle)
    body := fmt.Sprintf(
        "文章: %s\n作者: %s\n邮箱: %s\n时间: %s\nIP: %s\nUA: %s\n\n内容:\n%s\n",
        postTitle,
        escapeHTML(comment.Author),      // 安全转义
        escapeHTML(comment.Email),       // 安全转义
        comment.Timestamp,
        comment.IPAddress,
        escapeHTML(comment.UserAgent),   // 安全转义
        escapeHTML(comment.Content),     // 安全转义
    )

    msg := bytes.NewBuffer(nil)
    msg.WriteString("From: " + from + "\r\n")
    msg.WriteString("To: " + strings.Join(settings.SMTPTo, ",") + "\r\n")
    msg.WriteString("Subject: " + subject + "\r\n")
    msg.WriteString("MIME-Version: 1.0\r\n")
    msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
    msg.WriteString("\r\n")
    msg.WriteString(body)

    // 使用新的密码获取函数（支持加密密码和环境变量）
    password, err := getSMTPPassword(settings)
    if err != nil {
        log.Printf("[ERROR] Failed to get SMTP password: %v", err)
        return err
    }

    addr := settings.SMTPHost + ":" + strconv.Itoa(settings.SMTPPort)
    
    // 检查是否使用安全端口
    var tlsConfig *tls.Config
    if settings.SMTPPort == 465 {
        // SMTPS (隐式TLS)
        tlsConfig = &tls.Config{
            ServerName:         settings.SMTPHost,
            InsecureSkipVerify: false, // 生产环境必须验证证书
        }
    }
    
    auth := smtp.PlainAuth("", settings.SMTPUser, password, settings.SMTPHost)
    
    // 使用SendMail（添加TLS支持）
    if settings.SMTPPort == 465 {
        // SMTPS连接
        conn, err := tls.Dial("tcp", addr, tlsConfig)
        if err != nil {
            return err
        }
        defer conn.Close()
        
        client, err := smtp.NewClient(conn, settings.SMTPHost)
        if err != nil {
            return err
        }
        defer client.Close()
        
        if err := client.Auth(auth); err != nil {
            return err
        }
        
        if err := client.Mail(from); err != nil {
            return err
        }
        
        for _, to := range settings.SMTPTo {
            if err := client.Rcpt(to); err != nil {
                return err
            }
        }
        
        w, err := client.Data()
        if err != nil {
            return err
        }
        _, err = w.Write(msg.Bytes())
        if err != nil {
            return err
        }
        return w.Close()
    } else {
        // 标准SMTP + STARTTLS (端口587)
        log.Printf("[DEBUG] 连接到SMTP服务器: %s", addr)
        client, err := smtp.Dial(addr)
        if err != nil {
            log.Printf("[ERROR] SMTP连接失败: %v", err)
            return fmt.Errorf("SMTP连接失败: %w", err)
        }
        defer client.Close()
        
        // 升级到TLS
        log.Printf("[DEBUG] 启动TLS加密...")
        if err := client.StartTLS(&tls.Config{ServerName: settings.SMTPHost}); err != nil {
            log.Printf("[ERROR] TLS启动失败: %v", err)
            return fmt.Errorf("TLS启动失败: %w", err)
        }
        
        // 认证
        log.Printf("[DEBUG] 进行SMTP认证...")
        if err := client.Auth(auth); err != nil {
            log.Printf("[ERROR] SMTP认证失败: %v", err)
            return fmt.Errorf("SMTP认证失败: %w", err)
        }
        
        // 设置发件人
        log.Printf("[DEBUG] 设置发件人: %s", from)
        if err := client.Mail(from); err != nil {
            log.Printf("[ERROR] 设置发件人失败: %v", err)
            return fmt.Errorf("设置发件人失败: %w", err)
        }
        
        for _, to := range settings.SMTPTo {
            log.Printf("[DEBUG] 添加收件人: %s", to)
            if err := client.Rcpt(to); err != nil {
                log.Printf("[ERROR] 添加收件人失败: %v", err)
                return fmt.Errorf("添加收件人失败: %w", err)
            }
        }
        
        log.Printf("[DEBUG] 准备发送邮件数据...")
        w, err := client.Data()
        if err != nil {
            log.Printf("[ERROR] 启动数据传输失败: %v", err)
            return fmt.Errorf("启动数据传输失败: %w", err)
        }
        _, err = w.Write(msg.Bytes())
        if err != nil {
            log.Printf("[ERROR] 写入邮件内容失败: %v", err)
            return fmt.Errorf("写入邮件内容失败: %w", err)
        }
        
        if err := w.Close(); err != nil {
            log.Printf("[ERROR] 完成邮件发送失败: %v", err)
            return fmt.Errorf("完成邮件发送失败: %w", err)
        }
        
        log.Printf("[INFO] ✅ 邮件发送成功！收件人: %v", settings.SMTPTo)
        return nil
    }
}

type CommentWithPost struct {
    Comment
    PostTitle string `json:"post_title"`
}

func collectAllComments() ([]CommentWithPost, error) {
    var results []CommentWithPost
    contentRoot := filepath.Join(hugoPath, "content")
    if _, err := os.Stat(contentRoot); err != nil {
        return results, nil
    }

    err := filepath.Walk(contentRoot, func(path string, info os.FileInfo, err error) error {
        if err != nil || !info.IsDir() {
            return nil
        }
        commentsPath := filepath.Join(path, "comments.json")
        if _, err := os.Stat(commentsPath); err == nil {
            indexPath := filepath.Join(path, "index.md")
            comments, err := getComments(indexPath)
            if err != nil {
                return nil
            }
            content, err := os.ReadFile(indexPath)
            if err != nil {
                return nil
            }
            fm := parseFrontmatter(string(content))
            for _, c := range comments {
                relPath, _ := filepath.Rel(hugoPath, indexPath)
                c.PostPath = relPath
                results = append(results, CommentWithPost{Comment: c, PostTitle: fm.Title})
            }
        }
        return nil
    })

    if err != nil {
        return results, err
    }

    return results, nil
}

// ==================== 安全工具函数 ====================

// escapeHTML 安全地转义HTML特殊字符
func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// validateEmail 验证邮箱格式
func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// validatePath 严格验证路径，防止目录遍历
func validatePath(relPath, basePath string) (string, error) {
	// 规范化路径（多次Clean确保安全）
	cleaned := filepath.Clean(relPath)
	cleaned = filepath.Clean(cleaned)
	
	// 检查绝对路径
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths not allowed")
	}
	
	// 检查目录遍历
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") {
		return "", fmt.Errorf("directory traversal not allowed")
	}
	
	// Windows特定检查
	if strings.ContainsAny(cleaned, ":") {
		return "", fmt.Errorf("invalid characters in path")
	}
	
	// 构建完整路径
	fullPath := filepath.Join(basePath, cleaned)
	fullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	
	// 验证路径在基目录内
	basePath, _ = filepath.Abs(basePath)
	fullPathLower := strings.ToLower(fullPath)
	basePathLower := strings.ToLower(basePath)
	
	if !strings.HasPrefix(fullPathLower, basePathLower) {
		return "", fmt.Errorf("path outside base directory")
	}
	
	return fullPath, nil
}

// ==================== 密码加密管理 ====================

// getSMTPEncryptionKey 从环境变量获取加密密钥
func getSMTPEncryptionKey() ([]byte, error) {
	keyHex := os.Getenv("SMTP_ENCRYPTION_KEY")
	if keyHex == "" {
		// 如果没有设置密钥，返回错误
		return nil, fmt.Errorf("SMTP_ENCRYPTION_KEY not set in environment")
	}
	
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_ENCRYPTION_KEY format: %v", err)
	}
	
	// 验证密钥长度（应为32字节用于AES-256）
	if len(key) != 32 {
		return nil, fmt.Errorf("SMTP_ENCRYPTION_KEY must be 64 hex characters (32 bytes for AES-256)")
	}
	
	return key, nil
}

// encryptPassword 使用AES-256-GCM加密SMTP密码
func encryptPassword(plainPassword string) (string, error) {
	key, err := getSMTPEncryptionKey()
	if err != nil {
		return "", err
	}
	
	// 创建cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	
	// 创建GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	
	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	
	// 加密
	ciphertext := gcm.Seal(nonce, nonce, []byte(plainPassword), nil)
	
	// 返回base64编码的结果
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptPassword 解密SMTP密码
func decryptPassword(encryptedPassword string) (string, error) {
	key, err := getSMTPEncryptionKey()
	if err != nil {
		return "", err
	}
	
	// 解码base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("failed to decode password: %v", err)
	}
	
	// 创建cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}
	
	// 创建GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}
	
	// 提取nonce（前nonceSize字节）
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// 解密
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}
	
	return string(plaintext), nil
}

// getSMTPPassword 从配置或环境变量安全地获取SMTP密码
func getSMTPPassword(settings CommentSettings) (string, error) {
	// 优先从环境变量读取（用于生产环境）
	envPassword := os.Getenv("SMTP_PASSWORD")
	if envPassword != "" {
		return envPassword, nil
	}
	
	// 如果配置文件中的密码是加密的，则解密
	if settings.SMTPPass != "" {
		// 尝试解密（如果是加密的）
		decrypted, err := decryptPassword(settings.SMTPPass)
		if err == nil {
			return decrypted, nil
		}
		// 如果解密失败，返回原始值（可能是明文）
		log.Printf("[WARN] Failed to decrypt SMTP password, using plaintext: %v", err)
		return settings.SMTPPass, nil
	}
	
	return "", fmt.Errorf("SMTP password not found")
}

// ==================== JWT身份认证系统 ====================

var jwtSecret []byte

// initJWTSecret 初始化JWT密钥
func initJWTSecret() {
	// 优先从环境变量读取
	secretEnv := os.Getenv("JWT_SECRET")
	if secretEnv != "" {
		jwtSecret = []byte(secretEnv)
		return
	}
	
	// 从文件读取
	secretFile := filepath.Join(hugoPath, "config", ".jwt_secret")
	if secret, err := os.ReadFile(secretFile); err == nil {
		jwtSecret = secret
		return
	}
	
	// 生成新密钥
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		log.Fatalf("[FATAL] 无法生成JWT密钥，请设置JWT_SECRET环境变量: %v", err)
		return
	}
	
	jwtSecret = newSecret
	
	// 尝试保存到文件（用于后续使用）
	secretFile = filepath.Join(hugoPath, "config", ".jwt_secret")
	if err := os.WriteFile(secretFile, newSecret, 0600); err != nil {
		log.Printf("[WARN] Failed to save JWT secret: %v", err)
	}
}

type jwtClaims struct {
    Sub string `json:"sub"`
    Iat int64  `json:"iat"`
    Exp int64  `json:"exp"`
    Jti string `json:"jti"` // JWT ID for refresh token rotation
    Typ string `json:"typ"` // token type: "access" or "refresh"
}

// 刷新令牌存储 (内存存储，生产环境建议使用Redis)
var refreshTokenStore = make(map[string]int64) // jti -> expiry time
var refreshTokenMutex sync.RWMutex

func base64URLEncode(data []byte) string {
    return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
    return base64.RawURLEncoding.DecodeString(s)
}

func getJWTExpiry() time.Duration {
    if hoursStr := os.Getenv("JWT_TTL_HOURS"); hoursStr != "" {
        if hours, err := strconv.Atoi(hoursStr); err == nil && hours > 0 {
            return time.Duration(hours) * time.Hour
        }
    }
    return 8 * time.Hour
}

func signJWT(headerPayload string) string {
    h := hmac.New(sha256.New, jwtSecret)
    h.Write([]byte(headerPayload))
    return base64URLEncode(h.Sum(nil))
}

func createJWT(username string, tokenType string) (string, error) {
    if len(jwtSecret) == 0 {
        return "", fmt.Errorf("JWT secret not initialized")
    }
	
    header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
    jti := fmt.Sprintf("%s-%d-%s", username, time.Now().UnixNano(), generateRandomString(8))
    
    var expiry time.Duration
    if tokenType == "refresh" {
        expiry = 30 * 24 * time.Hour // 刷新令牌有效期30天
    } else {
        expiry = getJWTExpiry() // 访问令牌有效期从环境变量读取
    }
    
    claims := jwtClaims{
        Sub: username,
        Iat: time.Now().Unix(),
        Exp: time.Now().Add(expiry).Unix(),
        Jti: jti,
        Typ: tokenType,
    }
    claimsJSON, err := json.Marshal(claims)
    if err != nil {
        return "", err
    }
	
    payload := base64URLEncode(claimsJSON)
    unsigned := header + "." + payload
    signature := signJWT(unsigned)
    token := unsigned + "." + signature
    
    // 存储刷新令牌以支持令牌轮转
    if tokenType == "refresh" {
        refreshTokenMutex.Lock()
        refreshTokenStore[jti] = time.Now().Add(expiry).Unix()
        refreshTokenMutex.Unlock()
    }
    
    return token, nil
}

func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        randByte := make([]byte, 1)
        if _, err := rand.Read(randByte); err != nil {
            // fallback to sequential if rand fails
            b[i] = charset[i%len(charset)]
            continue
        }
        b[i] = charset[int(randByte[0])%len(charset)]
    }
    return string(b)
}

func verifyJWT(token string) (*jwtClaims, error) {
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid token format")
    }
    unsigned := parts[0] + "." + parts[1]
    expectedSig := signJWT(unsigned)
    if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(parts[2])) != 1 {
        return nil, fmt.Errorf("invalid token signature")
    }
	
    payloadBytes, err := base64URLDecode(parts[1])
    if err != nil {
        return nil, fmt.Errorf("invalid token payload")
    }
    var claims jwtClaims
    if err := json.Unmarshal(payloadBytes, &claims); err != nil {
        return nil, fmt.Errorf("invalid token claims")
    }
	
    now := time.Now().Unix()
    if claims.Exp <= now {
        return nil, fmt.Errorf("token expired")
    }
    if claims.Iat > now+60 {
        return nil, fmt.Errorf("token issued in the future")
    }
    
    // 检查刷新令牌是否被撤销
    if claims.Typ == "refresh" {
        refreshTokenMutex.RLock()
        expiry, exists := refreshTokenStore[claims.Jti]
        refreshTokenMutex.RUnlock()
        
        if !exists || expiry < now {
            return nil, fmt.Errorf("refresh token revoked or expired")
        }
    }
    
    return &claims, nil
}

func verifyAdminCredentials(username, password string) bool {
    adminUser := os.Getenv("ADMIN_USERNAME")
    if adminUser == "" {
        adminUser = "admin"
    }
    if username != adminUser {
        return false
    }
	
    passwordEnv := os.Getenv("ADMIN_PASSWORD")
    passwordHash := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_PASSWORD_HASH")))

    if passwordEnv == "" && passwordHash == "" {
        log.Printf("[ERROR] Admin password not configured")
        return false
    }
	
    if passwordHash != "" {
        sum := sha256.Sum256([]byte(password))
        calc := hex.EncodeToString(sum[:])
        result := subtle.ConstantTimeCompare([]byte(calc), []byte(passwordHash)) == 1
        return result
    }
	
    result := subtle.ConstantTimeCompare([]byte(password), []byte(passwordEnv)) == 1
    return result
}

func extractBearerToken(r *http.Request) string {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return ""
    }
    parts := strings.SplitN(authHeader, " ", 2)
    if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
        return ""
    }
    return strings.TrimSpace(parts[1])
}

func requireAuth(w http.ResponseWriter, r *http.Request) bool {
    // 如果未配置任何认证方式，仅允许本地访问
    adminTokenEnv := os.Getenv("ADMIN_TOKEN")
    adminPass := os.Getenv("ADMIN_PASSWORD")
    adminHash := os.Getenv("ADMIN_PASSWORD_HASH")
    if adminTokenEnv == "" && adminPass == "" && adminHash == "" {
        if !isLocalRequest(r) {
            respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "认证未配置"})
            return false
        }
        return true
    }
	
    // 兼容旧的X-Admin-Token
    if adminTokenEnv != "" {
        if r.Header.Get("X-Admin-Token") == adminTokenEnv {
            return true
        }
    }
	
    // JWT验证 (仅接受access令牌)
    token := extractBearerToken(r)
    if token != "" {
        claims, err := verifyJWT(token)
        if err == nil {
            // 检查令牌类型
            if claims.Typ == "access" || claims.Typ == "" {
                // 空的Typ表示旧版本的access令牌
                return true
            }
        }
    }
	
    respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "未授权"})
    return false
}

func withAuth(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !requireAuth(w, r) {
            return
        }
        handler(w, r)
    }
}

var auditLogMu sync.Mutex

func writeAuditLog(action string, r *http.Request, details map[string]interface{}) {
    auditLogMu.Lock()
    defer auditLogMu.Unlock()
	
    entry := map[string]interface{}{
        "ts":     time.Now().Format(time.RFC3339),
        "action": action,
        "ip":     getRealClientIP(r),
        "ua":     r.UserAgent(),
    }
    for k, v := range details {
        entry[k] = v
    }
	
    data, err := json.Marshal(entry)
    if err != nil {
        log.Printf("[WARN] Failed to marshal audit log: %v", err)
        return
    }
	
    logPath := filepath.Join(hugoPath, "config", "audit.log")
    file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
    if err != nil {
        log.Printf("[WARN] Failed to open audit log: %v", err)
        return
    }
    defer file.Close()
	
    _, _ = file.Write(append(data, '\n'))
}

// 定期轮转审计日志 (每天午夜或文件超过100MB时)
func rotateAuditLogPeriodically() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for range ticker.C {
        logPath := filepath.Join(hugoPath, "config", "audit.log")
        info, err := os.Stat(logPath)
        if err != nil {
            continue
        }

        // 检查文件大小是否超过100MB
        if info.Size() > 100*1024*1024 {
            rotateAuditLog(logPath)
        }
    }
}

// 执行日志轮转
func rotateAuditLog(logPath string) {
    auditLogMu.Lock()
    defer auditLogMu.Unlock()

    timestamp := time.Now().Format("2006-01-02-15-04-05")
    newName := logPath + "." + timestamp

    // 重命名当前日志文件
    if err := os.Rename(logPath, newName); err != nil {
        log.Printf("[AUDIT] Failed to rotate audit log: %v", err)
        return
    }

    // 压缩旧日志文件 (可选)
    go compressAuditLog(newName)

    // 清理超过30天的日志
    go cleanupOldAuditLogs(filepath.Dir(logPath))
}

// 压缩日志文件
func compressAuditLog(filePath string) {
    gzipPath := filePath + ".gz"
    inputFile, err := os.Open(filePath)
    if err != nil {
        return
    }
    defer inputFile.Close()

    outputFile, err := os.Create(gzipPath)
    if err != nil {
        return
    }
    defer outputFile.Close()

    writer := gzip.NewWriter(outputFile)
    defer writer.Close()

    if _, err := io.Copy(writer, inputFile); err != nil {
        return
    }

    // 删除原始文件
    os.Remove(filePath)
}

// 清理超过30天的日志
func cleanupOldAuditLogs(logDir string) {
    entries, err := os.ReadDir(logDir)
    if err != nil {
        return
    }

    cutoffTime := time.Now().AddDate(0, 0, -30)

    for _, entry := range entries {
        if !entry.IsDir() && strings.HasPrefix(entry.Name(), "audit.log.") {
            filePath := filepath.Join(logDir, entry.Name())
            info, err := entry.Info()
            if err != nil {
                continue
            }

            if info.ModTime().Before(cutoffTime) {
                os.Remove(filePath)
            }
        }
    }
}

// ==================== IP欺骗防护 ====================

// getRealClientIP 获取真实客户端IP，防止IP欺骗
func getRealClientIP(r *http.Request) string {
	// 优先检查可信代理的X-Forwarded-For头（仅在生产环境使用代理时）
	// 在开发环境，直接使用RemoteAddr
	isProxied := os.Getenv("BEHIND_PROXY") == "true"
	
	if isProxied {
		// 检查X-Forwarded-For（可信代理设置）
		forwarded := r.Header.Get("X-Forwarded-For")
		if forwarded != "" {
			// 取最后一个IP（直接连接的代理IP）
			ips := strings.Split(forwarded, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[len(ips)-1])
				if isValidIP(ip) {
					return ip
				}
			}
		}
		
		// 检查X-Real-IP
		realIP := r.Header.Get("X-Real-IP")
		if realIP != "" && isValidIP(realIP) {
			return realIP
		}
	}
	
	// 使用直接连接IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return ip
}

// isValidIP 验证IP地址格式
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func init() {
	var err error
	hugoPath, err = os.Getwd()
	if err != nil {
		panic(err)
	}
	
	// 初始化JWT密钥
	initJWTSecret()
    adminToken = os.Getenv("ADMIN_TOKEN")
}

// translateText translates text using MyMemory API
func translateText(text, sourceLang, targetLang string) string {
	escapedText := url.QueryEscape(text)
	apiURL := fmt.Sprintf("https://api.mymemory.translated.net/get?q=%s&langpair=%s|%s",
		escapedText, sourceLang, targetLang)

	resp, err := http.Get(apiURL)
	if err != nil {
		return text
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return text
	}

	if responseData, ok := result["responseData"].(map[string]interface{}); ok {
		if translated, ok := responseData["translatedText"].(string); ok {
			return translated
		}
	}

	return text
}

// ==================== 文件上传安全检查 ====================

// validateFileUpload 验证上传文件的安全性
func validateFileUpload(filename string, fileSize int64, contentType string, allowedMimeTypes map[string]bool, maxSize int64) error {
	// 1. 检查文件大小
	if fileSize <= 0 {
		return fmt.Errorf("invalid file size")
	}
	if fileSize > maxSize {
		return fmt.Errorf("file size exceeds limit: %d > %d", fileSize, maxSize)
	}
	
	// 2. 检查MIME类型
	if !allowedMimeTypes[contentType] {
		return fmt.Errorf("unsupported file type: %s", contentType)
	}
	
	// 3. 检查文件名
	if filename == "" {
		return fmt.Errorf("empty filename")
	}
	
	// 移除路径信息，只保留文件名
	filename = filepath.Base(filename)
	
	// 检查是否包含目录遍历字符
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return fmt.Errorf("invalid filename: path traversal detected")
	}
	
	// 4. 检查特殊字符
	validChars := regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)
	if !validChars.MatchString(filename) {
		return fmt.Errorf("filename contains invalid characters")
	}
	
	// 5. 检查双重扩展名（防止服务器配置漏洞）
	parts := strings.Split(filename, ".")
	if len(parts) > 2 {
		return fmt.Errorf("multiple extensions not allowed")
	}
	
	return nil
}

// detectImageMIME 更严格地检测图片MIME类型（检查文件头）
func detectImageMIME(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("file too small")
	}
	
	// PNG: 89 50 4E 47
	if bytes.Equal(data[0:4], []byte{0x89, 0x50, 0x4E, 0x47}) {
		return "image/png", nil
	}
	
	// JPEG: FF D8 FF
	if bytes.Equal(data[0:3], []byte{0xFF, 0xD8, 0xFF}) {
		return "image/jpeg", nil
	}
	
	// GIF: 47 49 46 38 (GIF8)
	if bytes.Equal(data[0:4], []byte{0x47, 0x49, 0x46, 0x38}) {
		return "image/gif", nil
	}
	
	// WebP: RIFF ... WEBP
	if len(data) >= 12 && bytes.Equal(data[0:4], []byte{0x52, 0x49, 0x46, 0x46}) &&
		bytes.Equal(data[8:12], []byte{0x57, 0x45, 0x42, 0x50}) {
		return "image/webp", nil
	}
	
	return "", fmt.Errorf("unsupported image format")
}

// getContent reads file content
func getContent(relPath string) (string, error) {
	// 验证路径安全性
	fullPath, err := validatePath(relPath, hugoPath)
	if err != nil {
		return "", fmt.Errorf("path validation failed: %v", err)
	}

	// 检查文件扩展名
	if !strings.HasSuffix(strings.ToLower(fullPath), ".md") {
		return "", fmt.Errorf("invalid file type")
	}

	if _, err := os.Stat(fullPath); err != nil {
		return "", fmt.Errorf("file not found")
	}

	content, err := os.ReadFile(fullPath)
	return string(content), err
}

// saveContent saves file content
func saveContent(relPath, content string) error {
	// 严格验证路径
	fullPath, err := validatePath(relPath, hugoPath)
	if err != nil {
		return fmt.Errorf("path validation failed: %v", err)
	}

	// 检查文件扩展名
	if !strings.HasSuffix(strings.ToLower(fullPath), ".md") {
		return fmt.Errorf("only .md files allowed")
	}

	// 记录审计日志
	log.Printf("[AUDIT] saveContent: path=%s", relPath)
	
	// 设置严格的文件权限（只有所有者可读写）
	return os.WriteFile(fullPath, []byte(content), 0600)
}

// deletePost deletes a post file
func deletePost(relPath string) error {
	// Normalize path separators
	relPath = strings.ReplaceAll(relPath, "/", string(os.PathSeparator))
	fullPath := filepath.Join(hugoPath, relPath)

	// Security check: must be .md file
	if !strings.HasSuffix(strings.ToLower(relPath), ".md") {
		return fmt.Errorf("only .md files can be deleted")
	}

	// Security check: must be within hugoPath
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return err
	}
	absHugo, _ := filepath.Abs(hugoPath)

	// Normalize paths for comparison (case-insensitive on Windows)
	absPathNorm := strings.ToLower(filepath.Clean(absPath))
	absHugoNorm := strings.ToLower(filepath.Clean(absHugo))

	if !strings.HasPrefix(absPathNorm, absHugoNorm) {
		return fmt.Errorf("path security violation: file must be within hugo directory")
	}

	// Check if file exists before attempting delete
	if _, err := os.Stat(fullPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", relPath)
		}
		return err
	}

	// Delete the file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to delete file: %v", err)
	}

	// Try to remove empty parent directory
	parentDir := filepath.Dir(fullPath)
	entries, err := os.ReadDir(parentDir)
	if err == nil && len(entries) == 0 {
		if err := os.Remove(parentDir); err == nil {
			// Successfully removed empty parent
		}
	}

	return nil
}

// parseFrontmatter extracts metadata from markdown file
func parseFrontmatter(content string) Frontmatter {
	fm := Frontmatter{Title: "Untitled", Draft: false, Date: time.Now().Format("2006-01-02")}

	if !strings.HasPrefix(content, "---") {
		return fm
	}

	parts := strings.Split(content, "---")
	if len(parts) < 3 {
		return fm
	}

	lines := strings.Split(parts[1], "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "title:") {
			fm.Title = strings.TrimSpace(strings.TrimPrefix(line, "title:"))
			fm.Title = strings.Trim(fm.Title, `"`)
		}

		if strings.HasPrefix(line, "draft:") && strings.Contains(strings.ToLower(line), "true") {
			fm.Draft = true
		}

		if strings.HasPrefix(line, "pinned:") && strings.Contains(strings.ToLower(line), "true") {
			fm.Pinned = true
		}

		if strings.HasPrefix(line, "date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "date:"))
			dateStr = strings.Trim(dateStr, `"`)
			if len(dateStr) >= 10 {
				fm.Date = dateStr[:10]
			}
		}
	}

	return fm
}

// extractPostTitle 从文章路径提取标题
func extractPostTitle(postPath string) string {
	fullPath := filepath.Join(hugoPath, postPath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		// 如果无法读取文件，返回路径作为标题
		return filepath.Base(postPath)
	}
	
	fm := parseFrontmatter(string(content))
	if fm.Title != "" && fm.Title != "Untitled" {
		return fm.Title
	}
	
	return filepath.Base(postPath)
}

// getGitStatus returns git status map
func getGitStatus() map[string]string {
	status := make(map[string]string)
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = hugoPath
	output, err := cmd.Output()
	if err != nil {
		return status
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if len(line) > 3 {
			stat := strings.TrimSpace(line[:2])
			path := strings.TrimSpace(line[3:])
			path = strings.ReplaceAll(path, `"`, "")
			status[path] = stat
		}
	}

	return status
}

// getPosts returns list of posts
func getPosts() []Post {
	var posts []Post
	gitStatus := getGitStatus()

	contentRoot := filepath.Join(hugoPath, "content")
	if _, err := os.Stat(contentRoot); err != nil {
		return posts
	}

	filepath.Walk(contentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".md") || strings.HasPrefix(info.Name(), "_") {
			return nil
		}

		relPath, _ := filepath.Rel(hugoPath, path)
		pathParts := strings.Split(strings.ToLower(relPath), string(os.PathSeparator))

		// Filter only posts
		hasPost := false
		for _, part := range pathParts {
			if part == "post" || part == "posts" {
				hasPost = true
				break
			}
		}

		if !hasPost {
			return nil
		}

		// Infer language
		lang := "en"
		if len(pathParts) > 1 && (pathParts[1] == "zh-cn" || pathParts[1] == "zh") {
			lang = pathParts[1]
		}

		// Get git status
		gStatus := "clean"
		normPath := strings.ReplaceAll(relPath, string(os.PathSeparator), "/")
		if s, ok := gitStatus[normPath]; ok {
			gStatus = s
		}

		// Read frontmatter
		content, _ := os.ReadFile(path)
		fm := parseFrontmatter(string(content))

		dateStr := time.Unix(info.ModTime().Unix(), 0).Format("2006-01-02")
		if fm.Date != "" {
			dateStr = fm.Date
		}

		// Determine status
		status := "PUBLISHED"
		color := "#22c55e"
		if fm.Draft {
			status = "DRAFT"
			color = "#eab308"
		} else if gStatus != "clean" {
			status = "UNSAVED"
			color = "#f97316"
		}

		posts = append(posts, Post{
			Title:       fm.Title,
			Lang:        lang,
			Path:        relPath,
			Date:        dateStr,
			Status:      status,
			StatusColor: color,
			Pinned:      fm.Pinned,
		})

		return nil
	})

	// Sort by pinned first, then by date descending, limit to 50
	sort.Slice(posts, func(i, j int) bool {
		if posts[i].Pinned != posts[j].Pinned {
			return posts[i].Pinned // pinned posts come first
		}
		return posts[i].Date > posts[j].Date
	})

	if len(posts) > 50 {
		posts = posts[:50]
	}

	return posts
}

// getCommentStats returns comment statistics for a post
func getCommentStats(postPath string) map[string]int {
	stats := map[string]int{
		"total":   0,
		"pending": 0,
	}

	comments, err := getComments(postPath)
	if err != nil {
		return stats
	}

	stats["total"] = len(comments)
	for _, c := range comments {
		if !c.Approved {
			stats["pending"]++
		}
	}

	return stats
}

// getAllCommentsStats returns statistics for all posts
func getAllCommentsStats() map[string]interface{} {
	totalPending := 0
	totalComments := 0
	postStats := make(map[string]map[string]int)

	posts := getPosts()
	for _, post := range posts {
		stats := getCommentStats(post.Path)
		postStats[post.Path] = stats
		totalComments += stats["total"]
		totalPending += stats["pending"]
	}

	return map[string]interface{}{
		"total_comments": totalComments,
		"total_pending":  totalPending,
		"post_stats":     postStats,
	}
}

// createSyncPost creates bilingual post
func createSyncPost(titleZh, categories string) (map[string]interface{}, error) {
	titleEn := translateText(titleZh, "zh", "en")
	filename := sanitizeFilename(titleEn)

	results := make(map[string]interface{})

	// Create zh-cn post
	zhPath := fmt.Sprintf("content/zh-cn/post/%s/index.md", filename)
	cmd := exec.Command("hugo", "new", zhPath)
	cmd.Dir = hugoPath
	if err := cmd.Run(); err == nil {
		updateFrontmatter(zhPath, titleZh, categories)
		results["zh_path"] = zhPath
	}

	// Create en post
	enPath := fmt.Sprintf("content/en/post/%s/index.md", filename)
	cmd = exec.Command("hugo", "new", enPath)
	cmd.Dir = hugoPath
	if err := cmd.Run(); err == nil {
		updateFrontmatter(enPath, titleEn, categories)
		results["en_path"] = enPath
	}

	return results, nil
}

// sanitizeFilename converts title to URL-safe filename
func sanitizeFilename(title string) string {
	reg := regexp.MustCompile("[^a-z0-9]+")
	s := strings.ToLower(title)
	s = reg.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// getCommentsPath returns the path to comments file for a post
func getCommentsPath(postPath string) string {
	// postPath format: content/zh-cn/post/example/index.md
	// comments file: content/zh-cn/post/example/comments.json
	dir := filepath.Dir(postPath)
	return filepath.Join(dir, "comments.json")
}

// getComments reads comments for a post
func getComments(postPath string) ([]Comment, error) {
	commentsPath := getCommentsPath(postPath)
	fullPath := filepath.Join(hugoPath, commentsPath)
	
	// If file doesn't exist, return empty list
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return []Comment{}, nil
	}
	
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	
	var cf CommentsFile
	if err := json.Unmarshal(content, &cf); err != nil {
		return nil, err
	}
	
	return cf.Comments, nil
}

// saveComments saves comments to file
func saveComments(postPath string, comments []Comment) error {
	commentsPath := getCommentsPath(postPath)
	fullPath := filepath.Join(hugoPath, commentsPath)
	
	cf := CommentsFile{Comments: comments}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(fullPath, data, 0644)
}

// addComment adds a new comment to a post
func addComment(postPath, author, email, content, ipAddress, userAgent, parentID string) (Comment, error) {
	comments, err := getComments(postPath)
	if err != nil {
        return Comment{}, err
	}
	
	// Generate unique ID
	id := fmt.Sprintf("%d-%d", time.Now().Unix(), len(comments))
	
	// Create new comment (not approved by default)
    comment := Comment{
		ID:        id,
		Author:    author,
		Email:     email,
		Content:   content,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Approved:  false,
		PostPath:  postPath,
		IPAddress: ipAddress,
		UserAgent: userAgent,
        ParentID:  parentID,
	}
	
	comments = append(comments, comment)
    return comment, saveComments(postPath, comments)
}

// approveComment approves a comment
func approveComment(postPath, commentID string) error {
	comments, err := getComments(postPath)
	if err != nil {
		return err
	}
	
	for i := range comments {
		if comments[i].ID == commentID {
			comments[i].Approved = true
			break
		}
	}
	
	return saveComments(postPath, comments)
}

// deleteGitHubIssue 删除或关闭GitHub Issue
func deleteGitHubIssue(issueNumber int, repo, token string) error {
	if issueNumber == 0 {
		return fmt.Errorf("invalid issue number")
	}
	
	// 使用PATCH请求关闭Issue（GitHub不支持真正删除Issue）
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d", repo, issueNumber)
	
	// 创建关闭Issue的请求体
	reqBody := map[string]string{
		"state": "closed",
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("PATCH", apiURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WSwriter")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("failed to read response: %v", readErr)
	}
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	// 解析响应确认状态
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err == nil {
		log.Printf("[INFO] GitHub Issue #%d closed - Response state: %v", issueNumber, result["state"])
	} else {
		log.Printf("[INFO] GitHub Issue #%d closed (response parse failed)", issueNumber)
	}
	return nil
}

// updateGitHubIssueLabels 更新GitHub Issue的标签
func updateGitHubIssueLabels(issueNumber int, repo, token string, labels []string) error {
	if issueNumber == 0 {
		return fmt.Errorf("invalid issue number")
	}
	
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d", repo, issueNumber)
	
	// 创建更新标签的请求体
	reqBody := map[string]interface{}{
		"labels": labels,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("PATCH", apiURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WSwriter")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		bodyText, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyText))
	}
	
	log.Printf("[INFO] GitHub Issue #%d labels updated to: %v", issueNumber, labels)
	return nil
}

// updateGitHubIssue 更新GitHub Issue的内容
func updateGitHubIssue(issueNumber int, repo, token string, comment Comment) error {
	if issueNumber == 0 {
		return fmt.Errorf("invalid issue number")
	}
	
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d", repo, issueNumber)
	
	// 构建Issue body
	body := fmt.Sprintf(`**Author:** %s
**Email:** %s
**Post:** %s
**Timestamp:** %s

**Content:**
%s`,
		comment.Author,
		comment.Email,
		comment.PostPath,
		comment.Timestamp,
		comment.Content)
	
	// 创建更新请求体
	reqBody := map[string]interface{}{
		"body": body,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	
	req, err := http.NewRequest("PATCH", apiURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WSwriter")
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		bodyText, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyText))
	}
	
	log.Printf("[INFO] GitHub Issue #%d updated successfully", issueNumber)
	return nil
}

// deleteComment deletes a comment
func deleteComment(postPath, commentID string) error {
	comments, err := getComments(postPath)
	if err != nil {
		return err
	}
	
	var filtered []Comment
	for _, c := range comments {
		if c.ID != commentID {
			filtered = append(filtered, c)
		}
	}
	
	return saveComments(postPath, filtered)
}

// updateFrontmatter updates post metadata
func updateFrontmatter(relPath, title, categories string) error {
	fullPath := filepath.Join(hugoPath, relPath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	
	// 转义标题中的双引号
	escapedTitle := strings.ReplaceAll(title, `"`, `\"`)

	for _, line := range lines {
		if strings.HasPrefix(line, "title:") {
			newLines = append(newLines, fmt.Sprintf(`title: "%s"`, escapedTitle))
		} else if strings.HasPrefix(line, "categories:") {
			cats := strings.Split(categories, ",")
			for i := range cats {
				cats[i] = strings.TrimSpace(cats[i])
			}
			catsJSON, _ := json.Marshal(cats)
			newLines = append(newLines, fmt.Sprintf(`categories: %s`, catsJSON))
		} else {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(fullPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// handleCommand executes system commands
func handleCommand(cmd string) (map[string]interface{}, error) {
	// 使用带超时的命令执行
	timeout := 5 * time.Minute // 默认5分钟超时
	
	switch cmd {
	case "preview":
		timeout = 10 * time.Second // 预览启动10秒超时
	case "deploy":
		timeout = 10 * time.Minute // 部署可能需要更长时间
	case "build":
		timeout = 5 * time.Minute
	case "sync":
		timeout = 3 * time.Minute
	}
	
	// 建立context用于超时控制
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	// 后续命令都通过ctx执行
	switch cmd {
	case "preview":
		// 先杀死可能占用端口的 hugo 进程
		killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer killCancel()
		
		if runtime.GOOS == "windows" {
			exec.CommandContext(killCtx, "taskkill", "/F", "/IM", "hugo.exe").Run()
		} else {
			exec.CommandContext(killCtx, "pkill", "hugo").Run()
		}
		
		time.Sleep(500 * time.Millisecond)
		
		// 先构建一次（包括草稿），确保所有内容都是最新的
		buildCmd := exec.CommandContext(ctx, "hugo", "--buildDrafts", "--minify")
		buildCmd.Dir = hugoPath
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("Build failed: %s", string(buildOutput))}, err
		}
		
		// 启动预览服务器（后台运行，包括草稿）
		serverCmd := exec.CommandContext(ctx, "hugo", "server", 
			"--bind", "127.0.0.1",
			"--buildDrafts",           // 显示草稿文章
			"--disableFastRender",     // 完整渲染，不使用快速渲染
			"--navigateToChanged")     // 保存文件时自动导航
		serverCmd.Dir = hugoPath
		
		go func() {
			// 让 hugo 服务器在后台持续运行
			serverCmd.Start()
		}()
		
		// 等待服务器启动
		time.Sleep(3 * time.Second)
		
		// 在主线程打开浏览器
		openBrowser("http://localhost:1313/WangScape/")
		
		return map[string]interface{}{
			"message": "✅ 预览服务器已启动（包括草稿），浏览器正在打开...",
			"url":     "http://localhost:1313/WangScape/",
		}, nil

	case "deploy":
		// 1. 先编译网站 - 不包含草稿（生产环境）
		buildCmd := exec.CommandContext(ctx, "hugo", "--minify")
		buildCmd.Dir = hugoPath
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("❌ Hugo 构建失败:\n%s\n\n请检查文章格式是否正确。", string(buildOutput))}, err
		}
		
		// 2. 检查是否有变更
		statusCmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
		statusCmd.Dir = hugoPath
		statusOutput, _ := statusCmd.Output()
		if len(strings.TrimSpace(string(statusOutput))) == 0 {
			return map[string]interface{}{"message": "ℹ️  没有任何文件变更，无需提交", "url": ""}, nil
		}
		
		// 3. Git 添加所有更改
		cmd := exec.CommandContext(ctx, "git", "add", ".")
		cmd.Dir = hugoPath
		if err := cmd.Run(); err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("❌ Git add 失败: %v", err)}, err
		}

		// 4. 提交更改
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		cmd = exec.Command("git", "commit", "-m", fmt.Sprintf("Web Update: %s", timestamp))
		cmd.Dir = hugoPath
		commitOutput, commitErr := cmd.CombinedOutput()
		if commitErr != nil && !strings.Contains(string(commitOutput), "nothing to commit") {
			return map[string]interface{}{"message": fmt.Sprintf("❌ Git commit 失败: %s", string(commitOutput))}, commitErr
		}

		// 5. 推送到远程
		cmd = exec.Command("git", "push")
		cmd.Dir = hugoPath
		pushOutput, pushErr := cmd.CombinedOutput()
		if pushErr != nil {
			errorMsg := string(pushOutput)
			if strings.Contains(errorMsg, "Permission denied") || strings.Contains(errorMsg, "authentication") {
				return map[string]interface{}{"message": "❌ 认证失败！\n\n请检查:\n1. SSH 密钥是否已配置\n2. GitHub 是否有访问权限\n3. 远程仓库地址是否正确", "url": ""}, pushErr
			} else if strings.Contains(errorMsg, "Connection refused") {
				return map[string]interface{}{"message": "❌ 网络连接失败！\n\n请检查:\n1. 网络是否正常\n2. 是否能访问 GitHub", "url": ""}, pushErr
			}
			return map[string]interface{}{"message": fmt.Sprintf("❌ Git push 失败:\n%s", errorMsg), "url": ""}, pushErr
		}

		return map[string]interface{}{"message": "✅ 构建成功！\n✅ 已提交文件\n✅ 已推送到 GitHub\n\n🎉 网站即将更新...", "url": ""}, nil

	default:
		return map[string]interface{}{"message": "Unknown command"}, nil
	}
}

// HTTP Handlers

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, htmlTemplate)
}

func handleGetPosts(w http.ResponseWriter, r *http.Request) {
	posts := getPosts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

func handleGetContent(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问
	if !requireLocal(w, r) {
		return
	}

	relPath := r.URL.Query().Get("path")
	if relPath == "" {
		http.Error(w, "Missing path", http.StatusBadRequest)
		return
	}

	content, err := getContent(relPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"content": content})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if !isLocalRequest(r) {
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "仅允许本地登录"})
        return
    }

    ip := getRealClientIP(r)
    if !allowRequest("login:"+ip, 10, time.Minute) {
        respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
        return
    }

    var data struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        log.Printf("[ERROR] Login request decode failed: %v", err)
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }
    data.Username = strings.TrimSpace(data.Username)
    
    if !verifyAdminCredentials(data.Username, data.Password) {
        log.Printf("[WARN] Login failed - Invalid credentials for user: %s", data.Username)
        writeAuditLog("login_failed", r, map[string]interface{}{"username": data.Username})
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "用户名或密码错误"})
        return
    }

    // 生成访问令牌 (短期)
    accessToken, err := createJWT(data.Username, "access")
    if err != nil {
        log.Printf("[ERROR] Failed to create access token: %v", err)
        writeAuditLog("login_error", r, map[string]interface{}{"username": data.Username, "error": err.Error()})
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成令牌失败"})
        return
    }

    // 生成刷新令牌 (长期)
    refreshToken, err := createJWT(data.Username, "refresh")
    if err != nil {
        log.Printf("[ERROR] Failed to create refresh token: %v", err)
        writeAuditLog("login_error", r, map[string]interface{}{"username": data.Username, "error": err.Error()})
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成刷新令牌失败"})
        return
    }

    accessExpiresAt := time.Now().Add(getJWTExpiry()).Format(time.RFC3339)
    refreshExpiresAt := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
    log.Printf("[INFO] Login successful - User: %s", data.Username)
    writeAuditLog("login_success", r, map[string]interface{}{"username": data.Username})
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "success":              true,
        "access_token":         accessToken,
        "refresh_token":        refreshToken,
        "access_expires_at":    accessExpiresAt,
        "refresh_expires_at":   refreshExpiresAt,
        "token_type":           "Bearer",
    })
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    if !isLocalRequest(r) {
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "仅允许本地刷新令牌"})
        return
    }

    var data struct {
        RefreshToken string `json:"refresh_token"`
    }
    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    // 验证刷新令牌
    claims, err := verifyJWT(data.RefreshToken)
    if err != nil {
        writeAuditLog("refresh_token_failed", r, map[string]interface{}{"error": err.Error()})
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "刷新令牌无效"})
        return
    }

    if claims.Typ != "refresh" {
        writeAuditLog("refresh_token_failed", r, map[string]interface{}{"error": "not a refresh token"})
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "令牌类型错误"})
        return
    }

    // 令牌轮转: 撤销旧刷新令牌并发放新的
    refreshTokenMutex.Lock()
    delete(refreshTokenStore, claims.Jti)
    refreshTokenMutex.Unlock()

    // 生成新的访问令牌和刷新令牌
    newAccessToken, err := createJWT(claims.Sub, "access")
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成令牌失败"})
        return
    }

    newRefreshToken, err := createJWT(claims.Sub, "refresh")
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成刷新令牌失败"})
        return
    }

    accessExpiresAt := time.Now().Add(getJWTExpiry()).Format(time.RFC3339)
    refreshExpiresAt := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
    writeAuditLog("refresh_token_success", r, map[string]interface{}{"username": claims.Sub})
    respondJSON(w, http.StatusOK, map[string]interface{}{
        "success":              true,
        "access_token":         newAccessToken,
        "refresh_token":        newRefreshToken,
        "access_expires_at":    accessExpiresAt,
        "refresh_expires_at":   refreshExpiresAt,
        "token_type":           "Bearer",
    })
}

func handleSaveContent(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问
	if !requireLocal(w, r) {
		return
	}

    // 限流：防止文件系统被滥用
    ip := getRealClientIP(r)
	if !allowRequest("save_content:"+ip, 30, time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
		return
	}

	var data struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := saveContent(data.Path, data.Content); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("save_content", r, map[string]interface{}{ "path": data.Path })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Saved"})
}

func handleDeletePost(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问
	if !requireLocal(w, r) {
		return
	}

    // 限流：防止文件被滥用删除
    ip := getRealClientIP(r)
	if !allowRequest("delete_post:"+ip, 10, time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
		return
	}

	var data struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := deletePost(data.Path); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("delete_post", r, map[string]interface{}{ "path": data.Path })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Deleted"})
}

// getCommentsFromGitHub 从GitHub Issues获取评论
func getCommentsFromGitHub(postPath, repo, token string) ([]Comment, error) {
	// 构建GitHub API URL - 只获取open状态的Issues
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues?state=open&labels=comment&per_page=100", repo)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WSwriter")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	var issues []struct {
		ID     int    `json:"id"`
		Number int    `json:"number"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		CreatedAt string `json:"created_at"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return nil, err
	}
	
	var comments []Comment
	for _, issue := range issues {
		// 从issue body解析评论字段
		body := issue.Body
		
		// 提取Post路径
		issuePostPath := extractField(body, "Post")
		if issuePostPath != postPath {
			continue
		}
		
		// 检查是否approved
		approved := false
		for _, label := range issue.Labels {
			if label.Name == "approved" {
				approved = true
				break
			}
		}
		
		// 只返回approved的评论
		if !approved {
			continue
		}
		
		comment := Comment{
			ID:          fmt.Sprintf("%d", issue.ID),
			Author:      extractField(body, "Author"),
			Email:       extractField(body, "Email"),
			Content:     extractContent(body),
			Timestamp:   issue.CreatedAt,
			Approved:    approved,
			PostPath:    issuePostPath,
			IssueNumber: issue.Number, // 保存Issue编号用于删除
		}
		
		// 调试日志：输出Issue body原始内容
		log.Printf("[DEBUG] GitHub Issue #%d body (first 500 chars): %s", issue.Number, func() string {
			if len(body) > 500 {
				return body[:500] + "..."
			}
			return body
		}())
		log.Printf("[DEBUG] Extracted comment - Author: %s, Email: %s, Content length: %d", comment.Author, comment.Email, len(comment.Content))
		
		comments = append(comments, comment)
	}
	
	return comments, nil
}

// extractField 从Issue body提取字段（支持Markdown格式）
func extractField(body, field string) string {
	lines := strings.Split(body, "\n")
	// 支持两种格式: "Field: value" 和 "**Field:** value"
	prefix1 := field + ":"
	prefix2 := "**" + field + ":**"
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix2) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix2))
		}
		if strings.HasPrefix(line, prefix1) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix1))
		}
	}
	return ""
}

// extractContent 提取评论内容
func extractContent(body string) string {
	lines := strings.Split(body, "\n")
	inContent := false
	var contentLines []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// 检查是否是元数据字段（Post, Author, Email, Timestamp等）
		if strings.HasPrefix(trimmed, "**Post:**") || 
		   strings.HasPrefix(trimmed, "**Author:**") || 
		   strings.HasPrefix(trimmed, "**Email:**") || 
		   strings.HasPrefix(trimmed, "**Timestamp:**") ||
		   strings.HasPrefix(trimmed, "Post:") || 
		   strings.HasPrefix(trimmed, "Author:") || 
		   strings.HasPrefix(trimmed, "Email:") || 
		   strings.HasPrefix(trimmed, "Timestamp:") {
			continue
		}
		
		// 支持两种格式: "Content:" 和 "**Content:**"
		if trimmed == "Content:" || trimmed == "**Content:**" {
			inContent = true
			continue
		}
		
		// 如果已经找到Content标记，或者是空行之后的内容（说明元数据结束了）
		if inContent || (trimmed != "" && len(contentLines) == 0 && !strings.Contains(trimmed, ":**")) {
			inContent = true
			contentLines = append(contentLines, line)
		} else if inContent || len(contentLines) > 0 {
			contentLines = append(contentLines, line)
		}
	}
	
	return strings.TrimSpace(strings.Join(contentLines, "\n"))
}

func handleGetComments(w http.ResponseWriter, r *http.Request) {
	postPath := r.URL.Query().Get("path")
	if postPath == "" {
		http.Error(w, "Missing path", http.StatusBadRequest)
		return
	}

	// 尝试从GitHub Issues获取评论
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape" // 从配置读取
	
	log.Printf("[DEBUG] GITHUB_TOKEN存在: %v, 长度: %d", githubToken != "", len(githubToken))
	
	if githubToken != "" && githubRepo != "" {
		log.Printf("[DEBUG] 尝试从GitHub获取评论: repo=%s, post=%s", githubRepo, postPath)
		comments, err := getCommentsFromGitHub(postPath, githubRepo, githubToken)
		if err == nil {
			log.Printf("[DEBUG] GitHub评论获取成功，数量: %d", len(comments))
			respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: comments})
			return
		}
		log.Printf("[DEBUG] GitHub评论获取失败: %v，降级到本地存储", err)
		// 如果GitHub失败，继续使用本地存储
	}

	// 降级：使用本地comments.json
	comments, err := getComments(postPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}

	// Return only approved comments for public view
	var approved []Comment
	for _, c := range comments {
		if c.Approved {
			approved = append(approved, c)
		}
	}

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: approved})
}

func handleAddComment(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

	var data struct {
		PostPath string   `json:"post_path"`
		Author   string   `json:"author"`
		Email    string   `json:"email"`
		Content  string   `json:"content"`
        ParentID string   `json:"parent_id"`
        Images   []string `json:"images"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

    // 使用新的IP获取函数，防止IP欺骗
    ipAddress := getRealClientIP(r)
    if !allowRequest("add_comment:"+ipAddress, 5, time.Minute) {
        respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
        return
    }

    // Get User-Agent
    userAgent := r.Header.Get("User-Agent")

    data.Author = strings.TrimSpace(data.Author)
    data.Email = strings.TrimSpace(data.Email)
    data.Content = strings.TrimSpace(data.Content)
    data.PostPath = strings.TrimSpace(data.PostPath)

    if data.Author == "" || data.Email == "" || data.Content == "" || data.PostPath == "" {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }
    cleanPostPath := filepath.Clean(data.PostPath)
    if filepath.IsAbs(cleanPostPath) || strings.HasPrefix(cleanPostPath, "..") || strings.Contains(cleanPostPath, ":") {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "路径非法"})
        return
    }
    if len(data.Author) > maxCommentNameLen || len(data.Email) > maxCommentEmailLen || len(data.Content) > maxCommentContentLen {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "内容过长"})
        return
    }
    if _, err := mail.ParseAddress(data.Email); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "邮箱格式不正确"})
        return
    }
    if len(data.Images) > maxCommentImages {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "图片数量过多"})
        return
    }
    for _, img := range data.Images {
        if !strings.HasPrefix(img, "/img/comments/") || strings.Contains(img, "..") {
            respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "图片路径非法"})
            return
        }
    }

    settings := loadCommentSettings()
    if isCommentBlacklisted(settings, ipAddress, data.Author, data.Email, data.Content) {
        respondJSON(w, http.StatusOK, APIResponse{Success: false, Message: "评论被拦截"})
        return
    }

    // 获取现有评论
    comments, err := getComments(data.PostPath)
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
        return
    }
    
    // 生成唯一ID
    id := fmt.Sprintf("%d-%d", time.Now().Unix(), len(comments))
    
    // 安全转义用户输入
    comment := Comment{
        ID:        id,
        Author:    escapeHTML(data.Author),    // 防XSS
        Email:     escapeHTML(data.Email),     // 防XSS
        Content:   escapeHTML(data.Content),   // 防XSS
        Timestamp: time.Now().Format("2006-01-02 15:04:05"),
        Approved:  false,
        PostPath:  data.PostPath,
        IPAddress: ipAddress,
        UserAgent: escapeHTML(userAgent),      // 防XSS
        ParentID:  data.ParentID,
        Images:    data.Images,
    }
    
    // 保存评论
    comments = append(comments, comment)
    if err := saveComments(data.PostPath, comments); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}

    // 记录审计日志
    log.Printf("[AUDIT] addComment: author=%s ip=%s path=%s approved=%v", 
        data.Author, ipAddress, data.PostPath, comment.Approved)

    // 发送邮件通知（不阻塞主流程）
    go func() {
        log.Printf("[DEBUG] 准备发送新评论通知邮件...")
        postTitle := ""
        fullPath := filepath.Join(hugoPath, data.PostPath)
        if content, err := os.ReadFile(fullPath); err == nil {
            fm := parseFrontmatter(string(content))
            postTitle = fm.Title
        }
        log.Printf("[DEBUG] 文章标题: %s", postTitle)
        if err := sendCommentNotification(settings, comment, postTitle); err != nil {
            log.Printf("[ERROR] 新评论通知邮件发送失败: %v", err)
        } else {
            log.Printf("[INFO] 新评论通知邮件已发送")
        }
    }()

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已提交，等待审核"})
}

func handleUploadCommentImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

    // 使用新的IP获取函数，防止IP欺骗
    ipAddress := getRealClientIP(r)
    if !allowRequest("upload_image:"+ipAddress, 10, time.Minute) {
        respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
        return
    }

	// 解析multipart form (最大10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "文件过大"})
		return
	}

	file, handler, err := r.FormFile("image")
	if err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "无法读取文件"})
		return
	}
	defer file.Close()

    if handler.Size > maxImageSize {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "文件过大"})
        return
    }

	// 检查文件类型
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}

    // 读取文件头判断真实类型（增强安全检查）
    head := make([]byte, 512)
    n, _ := file.Read(head)
    
    // 使用更严格的MIME类型检测
    contentType, err := detectImageMIME(head[:n])
    if err != nil {
        // 如果魔术字节检测失败，尝试标准检测
        contentType = http.DetectContentType(head[:n])
    }
    
    if !allowedTypes[contentType] {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "只支持 JPG, PNG, GIF, WebP 格式"})
		return
	}
    
    // 验证文件上传安全性
    if err := validateFileUpload(handler.Filename, handler.Size, contentType, allowedTypes, maxImageSize); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: fmt.Sprintf("文件验证失败: %v", err)})
        return
    }

    var reader io.Reader = file
    if seeker, ok := file.(io.Seeker); ok {
        _, _ = seeker.Seek(0, io.SeekStart)
    } else {
        reader = io.MultiReader(bytes.NewReader(head[:n]), file)
    }

	// 生成唯一文件名（不使用用户提供的文件名）
    extMap := map[string]string{
        "image/jpeg": ".jpg",
        "image/jpg":  ".jpg",
        "image/png":  ".png",
        "image/gif":  ".gif",
        "image/webp": ".webp",
    }
    ext := extMap[contentType]
	filename := fmt.Sprintf("comment_%d%s", time.Now().UnixNano(), ext)
	
	// 确保目录存在，权限设置为0755（仅owner可写）
	uploadDir := filepath.Join(hugoPath, "static", "img", "comments")
	os.MkdirAll(uploadDir, 0755)
	
	// 保存文件，权限设置为0600（仅owner可读写）
	dst, err := os.Create(filepath.Join(uploadDir, filename))
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "保存失败"})
		return
	}
	defer dst.Close()
    
    // 修改文件权限为0600
    os.Chmod(filepath.Join(uploadDir, filename), 0600)

    limitReader := io.LimitReader(reader, maxImageSize+1)
    written, err := io.Copy(dst, limitReader)
    if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "保存失败"})
		return
	}
    if written > maxImageSize {
        _ = os.Remove(filepath.Join(uploadDir, filename))
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "文件过大"})
        return
    }

	// 返回图片URL
	imageURL := "/img/comments/" + filename
	respondJSON(w, http.StatusOK, APIResponse{
		Success: true, 
		Message: "上传成功",
		Data:    map[string]string{"url": imageURL},
	})
}

func handleApproveComment(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感操作
	if !requireLocal(w, r) {
		return
	}

	var data struct {
		PostPath    string `json:"post_path"`
		CommentID   string `json:"comment_id"`
		IssueNumber int    `json:"issue_number,omitempty"` // GitHub Issue编号
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	// 如果有IssueNumber，说明是从GitHub Issues批准
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape"
	
	if data.IssueNumber > 0 && githubToken != "" && githubRepo != "" {
		log.Printf("[DEBUG] 批准GitHub Issue #%d", data.IssueNumber)
		// 将pending标签改为approved
		if err := updateGitHubIssueLabels(data.IssueNumber, githubRepo, githubToken, []string{"approved", "comment"}); err != nil {
			log.Printf("[ERROR] 更新GitHub Issue标签失败: %v", err)
			respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "更新GitHub Issue失败: " + err.Error()})
			return
		}
		log.Printf("[INFO] 成功批准GitHub Issue #%d", data.IssueNumber)
	} else {
		// 否则从本地文件批准
		log.Printf("[DEBUG] 从本地文件批准评论: %s", data.CommentID)
		if err := approveComment(data.PostPath, data.CommentID); err != nil {
			respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
			return
		}
	}
	
	// 发送邮件通知（审批操作）- 静默发送，不显示给访客
	go func() {
		settings := loadCommentSettings()
		postTitle := extractPostTitle(data.PostPath)
		comment := Comment{
			Author:    "管理员",
			Email:     "admin@system",
			Content:   fmt.Sprintf("评论 #%s 已被批准", data.CommentID),
			PostPath:  data.PostPath,
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		}
		if err := sendCommentNotification(settings, comment, "[批准] "+postTitle); err != nil {
			log.Printf("[DEBUG] 批准通知邮件发送失败: %v", err)
		} else {
			log.Printf("[DEBUG] 批准通知邮件已发送")
		}
	}()
	
    writeAuditLog("approve_comment", r, map[string]interface{}{ "post_path": data.PostPath, "comment_id": data.CommentID, "issue_number": data.IssueNumber })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已批准"})
}

func handleDeleteComment(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感操作
	if !requireLocal(w, r) {
		return
	}

	var data struct {
		PostPath    string `json:"post_path"`
		CommentID   string `json:"comment_id"`
		IssueNumber int    `json:"issue_number,omitempty"` // GitHub Issue编号
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	// 如果有IssueNumber，说明是从GitHub Issues删除
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape"
	
	if data.IssueNumber > 0 && githubToken != "" && githubRepo != "" {
		log.Printf("[DEBUG] 删除GitHub Issue #%d", data.IssueNumber)
		if err := deleteGitHubIssue(data.IssueNumber, githubRepo, githubToken); err != nil {
			log.Printf("[ERROR] 删除GitHub Issue失败: %v", err)
			respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "删除GitHub Issue失败: " + err.Error()})
			return
		}
		log.Printf("[INFO] 成功删除GitHub Issue #%d", data.IssueNumber)
	} else {
		// 否则从本地文件删除
		log.Printf("[DEBUG] 从本地文件删除评论: %s", data.CommentID)
		if err := deleteComment(data.PostPath, data.CommentID); err != nil {
			respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
			return
		}
	}
	
	// 发送邮件通知（删除操作）- 静默发送，不显示给访客
	go func() {
		settings := loadCommentSettings()
		postTitle := extractPostTitle(data.PostPath)
		comment := Comment{
			Author:    "管理员",
			Email:     "admin@system",
			Content:   fmt.Sprintf("评论 #%s 已被删除", data.CommentID),
			PostPath:  data.PostPath,
			Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		}
		if err := sendCommentNotification(settings, comment, "[删除] "+postTitle); err != nil {
			log.Printf("[DEBUG] 删除通知邮件发送失败: %v", err)
		} else {
			log.Printf("[DEBUG] 删除通知邮件已发送")
		}
	}()
	
    writeAuditLog("delete_comment", r, map[string]interface{}{ "post_path": data.PostPath, "comment_id": data.CommentID, "issue_number": data.IssueNumber })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已删除"})
}

func handleUpdateComment(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感操作
	if !requireLocal(w, r) {
		return
	}

	var data struct {
		PostPath    string `json:"post_path"`
		CommentID   string `json:"comment_id"`
		IssueNumber int    `json:"issue_number,omitempty"`
		Author      string `json:"author"`
		Email       string `json:"email"`
		Content     string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	// 如果有IssueNumber，说明是GitHub Issues评论
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape"
	
	if data.IssueNumber > 0 && githubToken != "" && githubRepo != "" {
		log.Printf("[DEBUG] 更新GitHub Issue #%d", data.IssueNumber)
		
		// 构建更新的评论对象
		updatedComment := Comment{
			Author:    data.Author,
			Email:     data.Email,
			Content:   data.Content,
			PostPath:  data.PostPath,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		
		if err := updateGitHubIssue(data.IssueNumber, githubRepo, githubToken, updatedComment); err != nil {
			log.Printf("[ERROR] 更新GitHub Issue失败: %v", err)
			respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "更新GitHub Issue失败: " + err.Error()})
			return
		}
		log.Printf("[INFO] 成功更新GitHub Issue #%d", data.IssueNumber)
		
		// 发送邮件通知（编辑操作）- 静默发送，不显示给访客
		go func() {
			settings := loadCommentSettings()
			postTitle := extractPostTitle(data.PostPath)
			if err := sendCommentNotification(settings, updatedComment, "[编辑] "+postTitle); err != nil {
				log.Printf("[DEBUG] 编辑通知邮件发送失败: %v", err)
			} else {
				log.Printf("[DEBUG] 编辑通知邮件已发送")
			}
		}()
	} else {
		// 本地文件的更新逻辑（如果需要）
		log.Printf("[DEBUG] 本地评论更新功能尚未实现")
		respondJSON(w, http.StatusNotImplemented, APIResponse{Success: false, Message: "本地评论更新功能尚未实现"})
		return
	}
	
	writeAuditLog("update_comment", r, map[string]interface{}{ "post_path": data.PostPath, "comment_id": data.CommentID, "issue_number": data.IssueNumber })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已更新"})
}

func handleGetAllComments(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感数据
	if !requireLocal(w, r) {
		return
	}

	postPath := r.URL.Query().Get("path")
	if postPath == "" {
		http.Error(w, "Missing path", http.StatusBadRequest)
		return
	}

	comments, err := getComments(postPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}

	// Return all comments (for admin view)
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: comments})
}

func handleCommentStats(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感数据
	if !requireLocal(w, r) {
		return
	}

	// 尝试从GitHub获取统计
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape"
	
	if githubToken != "" && githubRepo != "" {
		stats, err := getCommentStatsFromGitHub(githubRepo, githubToken)
		if err == nil {
			respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: stats})
			return
		}
	}

	// 降级：使用本地统计
	stats := getAllCommentsStats()
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: stats})
}

// getCommentStatsFromGitHub 从GitHub获取评论统计
func getCommentStatsFromGitHub(repo, token string) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues?state=all&labels=comment&per_page=100", repo)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "WSwriter")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	var issues []struct {
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return nil, err
	}
	
	total := len(issues)
	pending := 0
	approved := 0
	
	for _, issue := range issues {
		isPending := false
		isApproved := false
		
		for _, label := range issue.Labels {
			if label.Name == "pending" {
				isPending = true
			}
			if label.Name == "approved" {
				isApproved = true
			}
		}
		
		if isPending {
			pending++
		}
		if isApproved {
			approved++
		}
	}
	
	return map[string]interface{}{
		"total":    total,
		"pending":  pending,
		"approved": approved,
	}, nil
}

func handleGetPendingComments(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感数据
	if !requireLocal(w, r) {
		return
	}

	var pendingComments []CommentWithPost
	
	// 优先从GitHub Issues获取待审核评论
	githubToken := os.Getenv("GITHUB_TOKEN")
	githubRepo := "w2343419-del/WangScape"
	
	if githubToken != "" && githubRepo != "" {
		log.Printf("[DEBUG] 从GitHub获取待审核评论")
		apiURL := fmt.Sprintf("https://api.github.com/repos/%s/issues?state=open&labels=pending,comment&per_page=100", githubRepo)
		
		req, err := http.NewRequest("GET", apiURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+githubToken)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("User-Agent", "WSwriter")
			
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				
				if resp.StatusCode == 200 {
					var issues []struct {
						ID     int    `json:"id"`
						Number int    `json:"number"`
						Title  string `json:"title"`
						Body   string `json:"body"`
						State  string `json:"state"`
						CreatedAt string `json:"created_at"`
						Labels []struct {
							Name string `json:"name"`
						} `json:"labels"`
					}
					
					if json.NewDecoder(resp.Body).Decode(&issues) == nil {
						log.Printf("[DEBUG] GitHub返回 %d 条待审核Issues", len(issues))
						for _, issue := range issues {
							log.Printf("[DEBUG] Issue #%d - state: %s", issue.Number, issue.State)
						}
						for _, issue := range issues {
							body := issue.Body
							postPath := extractField(body, "Post")
							author := extractField(body, "Author")
							email := extractField(body, "Email")
							content := extractContent(body)
							
							// 调试日志
							log.Printf("[DEBUG] GitHub Issue #%d - Author: %s, Content length: %d", issue.Number, author, len(content))
							log.Printf("[DEBUG] Issue body preview: %s...", func() string {
								if len(body) > 200 {
									return body[:200]
								}
								return body
							}())
							
							// 检查是否有pending标签
							isPending := false
							for _, label := range issue.Labels {
								if label.Name == "pending" {
									isPending = true
									break
								}
							}
							
							if isPending {
								comment := Comment{
									ID:          fmt.Sprintf("%d", issue.ID),
									Author:      author,
									Email:       email,
									Content:     content,
									Timestamp:   issue.CreatedAt,
									Approved:    false,
									PostPath:    postPath,
									IssueNumber: issue.Number, // 保存Issue编号用于删除
								}
								
								pendingComments = append(pendingComments, CommentWithPost{
									Comment:   comment,
									PostTitle: issue.Title,
								})
							}
						}
						
						log.Printf("[DEBUG] 解析出 %d 条待审核评论", len(pendingComments))
						respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: pendingComments})
						return
					}
				}
			}
		}
		log.Printf("[DEBUG] GitHub获取失败，降级到本地存储")
	}

	// 降级：从本地comments.json读取
	contentRoot := filepath.Join(hugoPath, "content")
	filepath.Walk(contentRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		// 查找 comments.json 文件
		commentsPath := filepath.Join(path, "comments.json")
		if _, err := os.Stat(commentsPath); err == nil {
			comments, err := getComments(filepath.Join(path, "index.md"))
			if err == nil {
				// 获取文章标题
				indexPath := filepath.Join(path, "index.md")
				content, err := os.ReadFile(indexPath)
				if err == nil {
					fm := parseFrontmatter(string(content))
					for _, c := range comments {
						if !c.Approved {
							relPath, _ := filepath.Rel(hugoPath, indexPath)
							c.PostPath = relPath
							pendingComments = append(pendingComments, CommentWithPost{
								Comment:   c,
								PostTitle: fm.Title,
							})
						}
					}
				}
			}
		}
		return nil
	})

	// 按时间倒序排序
	sort.Slice(pendingComments, func(i, j int) bool {
		return pendingComments[i].Timestamp > pendingComments[j].Timestamp
	})

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: pendingComments})
}

func handleGetCommentSettings(w http.ResponseWriter, r *http.Request) {
    // 仅允许本地访问敏感配置
    if !requireLocal(w, r) {
        return
    }

    settings := loadCommentSettings()
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: settings})
}

func handleTestMail(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondJSON(w, http.StatusMethodNotAllowed, APIResponse{Success: false, Message: "Method not allowed"})
        return
    }

    // 仅允许本地访问
    if !requireLocal(w, r) {
        return
    }

    var data struct {
        SMTPHost string `json:"smtp_host"`
        SMTPPort int    `json:"smtp_port"`
        SMTPUser string `json:"smtp_user"`
        SMTPPass string `json:"smtp_pass"`
        SMTPFrom string `json:"smtp_from"`
        SMTPTo   string `json:"smtp_to"`
    }

    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    // 验证必要字段
    if data.SMTPHost == "" || data.SMTPPort == 0 || data.SMTPUser == "" || data.SMTPPass == "" || data.SMTPTo == "" {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "缺少必要的SMTP配置参数"})
        return
    }

    // 创建临时配置用于测试
    testSettings := CommentSettings{
        SMTPEnabled: true,
        SMTPHost:    data.SMTPHost,
        SMTPPort:    data.SMTPPort,
        SMTPUser:    data.SMTPUser,
        SMTPPass:    data.SMTPPass,
        SMTPFrom:    data.SMTPFrom,
        SMTPTo:      []string{data.SMTPTo},
    }

    // 创建测试邮件
    testComment := Comment{
        Author:    "测试用户",
        Email:     "test@example.com",
        Content:   "这是一封测试邮件，说明您的SMTP配置正确。",
        Timestamp: time.Now().Format("2006-01-02 15:04:05"),
        IPAddress: "127.0.0.1",
    }

    // 发送测试邮件
    if err := sendCommentNotification(testSettings, testComment, "测试文章"); err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "邮件发送失败: " + err.Error()})
        log.Printf("[ERROR] Test email failed: %v", err)
        return
    }

    writeAuditLog("test_mail", r, map[string]interface{}{"smtp_host": data.SMTPHost})
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "测试邮件已发送，请检查收件箱"})
}

func handleSaveCommentSettings(w http.ResponseWriter, r *http.Request) {
    // 仅允许本地访问敏感配置
    if !requireLocal(w, r) {
        return
    }

    var settings CommentSettings
    if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    if err := saveCommentSettings(settings); err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
        return
    }
    writeAuditLog("save_comment_settings", r, map[string]interface{}{"smtp_enabled": settings.SMTPEnabled})
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Saved"})
}

func handleBulkComments(w http.ResponseWriter, r *http.Request) {
    // 仅允许本地访问敏感操作
    if !requireLocal(w, r) {
        return
    }

    var data struct {
        Action string `json:"action"`
        Items  []struct {
            PostPath    string `json:"post_path"`
            CommentID   string `json:"comment_id"`
            IssueNumber int    `json:"issue_number,omitempty"`
        } `json:"items"`
    }

    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    if data.Action != "approve" && data.Action != "delete" {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid action"})
        return
    }

    githubToken := os.Getenv("GITHUB_TOKEN")
    githubRepo := "w2343419-del/WangScape"
    successCount := 0
    failCount := 0

    for _, item := range data.Items {
        if item.IssueNumber > 0 && githubToken != "" && githubRepo != "" {
            // 使用GitHub API批量操作
            if data.Action == "approve" {
                if err := updateGitHubIssueLabels(item.IssueNumber, githubRepo, githubToken, []string{"approved", "comment"}); err != nil {
                    log.Printf("[ERROR] 批量批准Issue #%d失败: %v", item.IssueNumber, err)
                    failCount++
                } else {
                    successCount++
                }
            } else {
                if err := deleteGitHubIssue(item.IssueNumber, githubRepo, githubToken); err != nil {
                    log.Printf("[ERROR] 批量删除Issue #%d失败: %v", item.IssueNumber, err)
                    failCount++
                } else {
                    successCount++
                }
            }
        } else {
            // 本地文件操作
            if data.Action == "approve" {
                if err := approveComment(item.PostPath, item.CommentID); err != nil {
                    failCount++
                } else {
                    successCount++
                }
            } else {
                if err := deleteComment(item.PostPath, item.CommentID); err != nil {
                    failCount++
                } else {
                    successCount++
                }
            }
        }
    }
    
    writeAuditLog("bulk_comments", r, map[string]interface{}{"action": data.Action, "count": len(data.Items), "success": successCount, "fail": failCount})
    
    var message string
    if failCount > 0 {
        message = fmt.Sprintf("批量操作完成：成功 %d 条，失败 %d 条", successCount, failCount)
    } else {
        message = fmt.Sprintf("批量操作成功：%d 条", successCount)
    }
    
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: message})
}

func handleExportComments(w http.ResponseWriter, r *http.Request) {
    // 仅允许本地访问敏感数据
    if !requireLocal(w, r) {
        return
    }

    comments, err := collectAllComments()
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
        return
    }

    writeAuditLog("export_comments", r, map[string]interface{}{"count": len(comments)})

    w.Header().Set("Content-Type", "text/csv; charset=utf-8")
    w.Header().Set("Content-Disposition", "attachment; filename=comments.csv")

    writer := csv.NewWriter(w)
    _ = writer.Write([]string{"post_path", "post_title", "id", "author", "email", "content", "timestamp", "approved", "ip_address", "user_agent", "parent_id"})
    for _, c := range comments {
        _ = writer.Write([]string{
            c.PostPath,
            c.PostTitle,
            c.ID,
            c.Author,
            c.Email,
            c.Content,
            c.Timestamp,
            strconv.FormatBool(c.Approved),
            c.IPAddress,
            c.UserAgent,
            c.ParentID,
        })
    }
    writer.Flush()
}

func handleCreateSync(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Title      string `json:"title"`
		Categories string `json:"categories"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	results, err := createSyncPost(data.Title, data.Categories)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("create_sync_post", r, map[string]interface{}{ "title": data.Title, "categories": data.Categories })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: results})
}

func handleCommandAPI(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感命令
	if !requireLocal(w, r) {
		return
	}

    // 限流：防止命令执行被滥用
    ip := getRealClientIP(r)
	if !allowRequest("command:"+ip, 10, time.Minute) {
		respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
		return
	}

	cmd := r.URL.Query().Get("name")
	if cmd == "" {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Missing command"})
		return
	}

	// 限制命令为预定义的安全命令
	allowedCmds := map[string]bool{
		"preview": true,
		"deploy":  true,
		"build":   true,
		"sync":    true,
	}
	if !allowedCmds[cmd] {
		respondJSON(w, http.StatusForbidden, APIResponse{Success: false, Message: "Unknown command"})
		return
	}

	result, err := handleCommand(cmd)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("command_exec", r, map[string]interface{}{ "command": cmd })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: result})
}

// handleSyncTranslate translates markdown content and syncs to English version
func handleSyncTranslate(w http.ResponseWriter, r *http.Request) {
	var data struct {
		ZhPath  string `json:"zhPath"`
		EnPath  string `json:"enPath"`
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	// 检查英文版本是否存在
	enFullPath := filepath.Join(hugoPath, data.EnPath)
	if _, err := os.Stat(enFullPath); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "English version not found"})
		return
	}

	// 解析 frontmatter 和内容
	parts := strings.Split(data.Content, "---")
	if len(parts) < 3 {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid markdown format"})
		return
	}

	// 获取中文版本的 frontmatter
	zhFrontmatter := parts[1]
	zhBody := strings.Join(parts[2:], "---")

	// 翻译内容正文（保留代码块和特殊标记不翻译）
	translatedBody := translateMarkdownContent(zhBody, "zh", "en")

	// 生成英文版本的 frontmatter（替换标题）
	enFrontmatter := zhFrontmatter
	titleMatch := regexp.MustCompile(`title:\s*"?([^"\n]+)"?`).FindStringSubmatch(zhFrontmatter)
	if len(titleMatch) > 1 {
		zhTitle := titleMatch[1]
		enTitle := translateText(zhTitle, "zh", "en")
		enFrontmatter = regexp.MustCompile(`title:\s*"?[^"\n]+"?`).ReplaceAllString(zhFrontmatter, fmt.Sprintf(`title: "%s"`, enTitle))
	}

	// 组装英文版本
	enContent := "---" + enFrontmatter + "---" + translatedBody

	// 保存英文版本
	if err := os.WriteFile(enFullPath, []byte(enContent), 0644); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: fmt.Sprintf("Failed to save: %v", err)})
		return
	}
    writeAuditLog("sync_translate", r, map[string]interface{}{ "zh_path": data.ZhPath, "en_path": data.EnPath })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Content translated and synced"})
}

// translateMarkdownContent translates markdown body while preserving code blocks
func translateMarkdownContent(content, sourceLang, targetLang string) string {
	// 临时替换代码块
	codeBlocks := []string{}
	codeRegex := regexp.MustCompile("```[\\s\\S]*?```")
	content = codeRegex.ReplaceAllStringFunc(content, func(match string) string {
		codeBlocks = append(codeBlocks, match)
		return fmt.Sprintf("__CODE_BLOCK_%d__", len(codeBlocks)-1)
	})

	// 分段翻译（避免超过 API 限制）
	paragraphs := strings.Split(content, "\n\n")
	for i, para := range paragraphs {
		if len(strings.TrimSpace(para)) > 0 && !strings.HasPrefix(para, "#") {
			paragraphs[i] = translateText(para, sourceLang, targetLang)
		}
	}
	content = strings.Join(paragraphs, "\n\n")

	// 恢复代码块
	for i, block := range codeBlocks {
		placeholder := fmt.Sprintf("__CODE_BLOCK_%d__", i)
		content = strings.ReplaceAll(content, placeholder, block)
	}

	return content
}

func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func withCORS(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "" {
            if !isAllowedOrigin(origin, r) {
                // 拒绝不信任的origin，不暴露任何信息
                w.Header().Set("X-Frame-Options", "DENY")
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            // 只有白名单origin才允许跨域访问
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Vary", "Origin")
            
            // 严格的CORS策略
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Token")
            w.Header().Set("Access-Control-Max-Age", "3600")
            w.Header().Set("Access-Control-Allow-Credentials", "false")
            w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
        }
        
        // 安全响应头
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        
        // 处理预检请求
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        
        handler(w, r)
    }
}

func isAllowedOrigin(origin string, r *http.Request) bool {
    allowed := map[string]bool{
        "http://localhost:1313":  true,
        "http://127.0.0.1:1313": true,
        "http://localhost:8080":  true,
        "http://127.0.0.1:8080": true,
        "https://localhost:1313":  true,
        "https://127.0.0.1:1313": true,
        "https://localhost:8080":  true,
        "https://127.0.0.1:8080": true,
    }

    // 允许与当前Host一致的来源
    if r != nil {
        hostOriginHTTP := "http://" + r.Host
        hostOriginHTTPS := "https://" + r.Host
        allowed[hostOriginHTTP] = true
        allowed[hostOriginHTTPS] = true
    }

    // 允许 BASE_URL
    if baseURL := strings.TrimSpace(os.Getenv("BASE_URL")); baseURL != "" {
        allowed[baseURL] = true
    }

    // 允许自定义来源列表 ALLOWED_ORIGINS (逗号分隔)
    if raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); raw != "" {
        parts := strings.Split(raw, ",")
        for _, p := range parts {
            p = strings.TrimSpace(p)
            if p != "" {
                allowed[p] = true
            }
        }
    }

    return allowed[origin]
}

func getClientIP(r *http.Request) string {
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress != "" {
		parts := strings.Split(ipAddress, ",")
		return strings.TrimSpace(parts[0])
	}
	if ipAddress = r.Header.Get("X-Real-IP"); ipAddress != "" {
		return ipAddress
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isLocalRequest(r *http.Request) bool {
    ip := getRealClientIP(r)
	return ip == "127.0.0.1" || ip == "localhost" || ip == "::1"
}

// getEnv 获取环境变量，如果未设置则返回默认值
func getEnv(key, defaultValue string) string {
    value := os.Getenv(key)
    if value == "" {
        return defaultValue
    }
    return value
}

func requireLocal(w http.ResponseWriter, r *http.Request) bool {
    if isLocalRequest(r) {
        return true
    }
    // 允许通过认证的远程访问
    if requireAuth(w, r) {
        return true
    }
    return false
}

func requireAdminToken(r *http.Request) bool {
	if adminToken == "" {
		return true
	}
	token := r.Header.Get("X-Admin-Token")
	return token == adminToken
}

func allowRequest(key string, limit int, window time.Duration) bool {
    if limit <= 0 {
        return true
    }
    
    now := time.Now()
    cutoff := now.Add(-window)

    rateLimiter.Lock()
    defer rateLimiter.Unlock()

    items := rateLimiter.records[key]
    
    // 过滤掉超时的记录（时间窗口外的请求）
    filtered := items[:0]
    for _, t := range items {
        if t.After(cutoff) {
            filtered = append(filtered, t)
        }
    }
    
    // 检查是否达到限制
    if len(filtered) >= limit {
        rateLimiter.records[key] = filtered
        log.Printf("[RATE_LIMIT] Key=%s, Requests=%d, Limit=%d, Window=%v", key, len(filtered), limit, window)
        return false
    }
    
    // 添加新请求
    filtered = append(filtered, now)
    rateLimiter.records[key] = filtered
    
    // 定期清理过期记录（避免内存泄漏）
    if len(rateLimiter.records) > 10000 {
        // 清理所有过期的记录
        for k, v := range rateLimiter.records {
            newV := v[:0]
            for _, t := range v {
                if t.After(cutoff) {
                    newV = append(newV, t)
                }
            }
            if len(newV) == 0 {
                delete(rateLimiter.records, k)
            } else {
                rateLimiter.records[k] = newV
            }
        }
    }
    
    return true
}

// openBrowser opens the default browser
func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Run()
	case "linux":
		exec.Command("xdg-open", url).Run()
	case "windows":
		exec.Command("cmd", "/c", "start", url).Run()
	}
}

func limitRequestBody(h http.HandlerFunc, maxSize int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxSize)
		h(w, r)
	}
}

// loadEnvFile 从.env文件加载环境变量
func loadEnvFile(filename string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		// .env文件不存在时忽略，使用系统环境变量
		return
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// 解析 KEY=VALUE 格式
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// 移除引号（如果有）
		if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
			(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
			value = value[1 : len(value)-1]
		}
		
		// 设置环境变量（仅当未设置时）
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}

func main() {
	// 加载.env文件
	loadEnvFile(".env")
	
	// 调试：打印加载的凭据
	adminUser := os.Getenv("ADMIN_USERNAME")
	adminPass := os.Getenv("ADMIN_PASSWORD")
	githubToken := os.Getenv("GITHUB_TOKEN")
	if adminUser != "" || adminPass != "" {
		log.Printf("[AUTH] 凭据已加载 - User: %s, Password: %s", adminUser, "***")
	}
	if githubToken != "" {
		log.Printf("[AUTH] GITHUB_TOKEN已加载，长度: %d", len(githubToken))
	} else {
		log.Printf("[WARN] GITHUB_TOKEN未设置，无法从GitHub读取评论")
	}
	
	// ==================== 安全中间件设置 ====================
	
	// 添加HSTS和其他安全头
	hstsMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS: 强制HTTPS连接 (1年有效期)
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			// 防止MIME嗅探
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// XSS防护
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			// 禁用iframe嵌入
			w.Header().Set("X-Frame-Options", "DENY")
			// 限制特性权限
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			// Content Security Policy
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com")
			
			next.ServeHTTP(w, r)
		})
	}
	
	// 创建根mux并包装HSTS中间件
	rootMux := http.NewServeMux()
	wrappedMux := hstsMiddleware(rootMux)
	
	// Setup routes
	rootMux.HandleFunc("/", handleIndex)
    rootMux.HandleFunc("/api/login", withCORS(limitRequestBody(handleLogin, 4<<10)))
    rootMux.HandleFunc("/api/refresh-token", withCORS(limitRequestBody(handleRefreshToken, 4<<10)))
    rootMux.HandleFunc("/api/posts", withCORS(handleGetPosts))
    rootMux.HandleFunc("/api/get_content", withCORS(withAuth(handleGetContent)))
    rootMux.HandleFunc("/api/save_content", withCORS(withAuth(limitRequestBody(handleSaveContent, 2<<20))))
    rootMux.HandleFunc("/api/delete_post", withCORS(withAuth(limitRequestBody(handleDeletePost, 1<<20))))
    rootMux.HandleFunc("/api/create_sync", withCORS(withAuth(limitRequestBody(handleCreateSync, 5<<20))))
    rootMux.HandleFunc("/api/sync_translate", withCORS(withAuth(limitRequestBody(handleSyncTranslate, 5<<20))))
    rootMux.HandleFunc("/api/command", withCORS(withAuth(limitRequestBody(handleCommandAPI, 512))))
    rootMux.HandleFunc("/api/comments", withCORS(handleGetComments))
    rootMux.HandleFunc("/api/add_comment", withCORS(limitRequestBody(handleAddComment, 1<<20)))
    rootMux.HandleFunc("/api/upload_comment_image", withCORS(limitRequestBody(handleUploadCommentImage, 12<<20)))
    rootMux.HandleFunc("/api/approve_comment", withCORS(withAuth(limitRequestBody(handleApproveComment, 512))))
    rootMux.HandleFunc("/api/delete_comment", withCORS(withAuth(limitRequestBody(handleDeleteComment, 512))))
    rootMux.HandleFunc("/api/update_comment", withCORS(withAuth(limitRequestBody(handleUpdateComment, 2<<20))))
    rootMux.HandleFunc("/api/all_comments", withCORS(withAuth(handleGetAllComments)))
    rootMux.HandleFunc("/api/comment_stats", withCORS(withAuth(handleCommentStats)))
    rootMux.HandleFunc("/api/pending_comments", withCORS(withAuth(handleGetPendingComments)))
    rootMux.HandleFunc("/api/comment_settings", withCORS(withAuth(handleGetCommentSettings)))
    rootMux.HandleFunc("/api/save_comment_settings", withCORS(withAuth(limitRequestBody(handleSaveCommentSettings, 1<<20))))
    rootMux.HandleFunc("/api/test_mail", withCORS(withAuth(limitRequestBody(handleTestMail, 1<<20))))
    rootMux.HandleFunc("/api/bulk_comments", withCORS(withAuth(limitRequestBody(handleBulkComments, 1<<20))))
    rootMux.HandleFunc("/api/export_comments", withCORS(withAuth(handleExportComments)))

	// 启动审计日志轮转
	go rotateAuditLogPeriodically()

	// 获取端口配置
    httpHost := getEnv("HTTP_HOST", "127.0.0.1")
    httpsHost := getEnv("HTTPS_HOST", httpHost)
	httpPort := getEnv("HTTP_PORT", "8080")
	httpsPort := getEnv("HTTPS_PORT", "443")
	tlsCertFile := getEnv("TLS_CERT_FILE", "")
	tlsKeyFile := getEnv("TLS_KEY_FILE", "")

	// Start HTTP server
    openHost := httpHost
    if openHost == "0.0.0.0" || openHost == "::" {
        openHost = "127.0.0.1"
    }
    fmt.Printf("WangScape Writer Online: http://%s:%s\n", openHost, httpPort)
    openBrowser(fmt.Sprintf("http://%s:%s", openHost, httpPort))

	// 启动HTTP监听
	go func() {
        httpAddr := fmt.Sprintf("%s:%s", httpHost, httpPort)
		if err := http.ListenAndServe(httpAddr, wrappedMux); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[AUDIT] HTTP Server error: %v\n", err)
		}
	}()

	// 启动HTTPS监听 (如果配置了证书)
	if tlsCertFile != "" && tlsKeyFile != "" {
		if _, err := os.Stat(tlsCertFile); err == nil {
			if _, err := os.Stat(tlsKeyFile); err == nil {
				go func() {
                    httpsAddr := fmt.Sprintf("%s:%s", httpsHost, httpsPort)
					fmt.Printf("[AUDIT] HTTPS Server starting on %s\n", httpsAddr)
					if err := http.ListenAndServeTLS(httpsAddr, tlsCertFile, tlsKeyFile, wrappedMux); err != nil && err != http.ErrServerClosed {
						fmt.Printf("[AUDIT] HTTPS Server error: %v\n", err)
					}
				}()
			} else {
				fmt.Printf("[AUDIT] TLS key file not found: %s\n", tlsKeyFile)
			}
		} else {
			fmt.Printf("[AUDIT] TLS cert file not found: %s\n", tlsCertFile)
		}
	} else {
		fmt.Printf("[AUDIT] HTTPS not configured (set TLS_CERT_FILE and TLS_KEY_FILE to enable)\n")
	}

	// 持续运行
	select {}
}

var htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WangScape Writer</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Sitka+Small&family=Noto+Sans+SC:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --dash-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --dash-sidebar: #1e293b;
            --dash-text: #0f172a;
            --dash-text-dim: #64748b;
            --dash-accent: #6366f1;
            --dash-border: #e2e8f0;
            --word-bg: #f1f5f9;
            --word-blue: #3b82f6;
            --word-paper: #ffffff;
            --word-text: #0f172a;
            --word-border: #e2e8f0;
            --font-main: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
        }

        * {
            box-sizing: border-box;
        }
        
        body {
            margin: 0;
            font-family: var(--font-main);
            overflow: hidden;
            height: 100vh;
            background: #f8fafc;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .view-section {
            display: none;
            width: 100%;
            height: 100%;
        }

        .view-section.active {
            display: flex;
        }

        #dashboard-view {
            background: var(--dash-bg);
            color: var(--dash-text);
        }

        .dash-sidebar {
            width: 280px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-right: 1px solid #e2e8f0;
            padding: 32px 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            box-shadow: 4px 0 24px rgba(0, 0, 0, 0.06);
            --dash-text: #0f172a;
            --dash-text-dim: #64748b;
            position: relative;
            z-index: 10;
        }
        
        .dash-sidebar::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 200px;
            background: linear-gradient(180deg, rgba(99, 102, 241, 0.05) 0%, transparent 100%);
            pointer-events: none;
        }

        .dash-logo {
            font-size: 22px;
            font-weight: 800;
            background: linear-gradient(135deg, #a5b4fc 0%, #4f46e5 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            letter-spacing: 0.2px;
        }

        .dash-btn {
            background: rgba(99, 102, 241, 0.05);
            border: 1px solid #e2e8f0;
            color: #0f172a;
            padding: 12px 16px;
            border-radius: 10px;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 500;
            position: relative;
            overflow: hidden;
        }
        
        .dash-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .dash-btn:hover::before {
            left: 100%;
        }

        .dash-btn:hover {
            border-color: #c7d2fe;
            background: rgba(99, 102, 241, 0.12);
            color: #4338ca;
            transform: translateX(4px);
        }
        
        .dash-btn:active {
            transform: scale(0.98);
        }

        .dash-btn.primary {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: #ffffff;
            border: none;
            font-weight: 600;
            box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4), inset 0 1px 0 rgba(255,255,255,0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }
        
        .dash-btn.primary::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255,255,255,0.3);
            transition: width 0.6s, height 0.6s;
        }
        
        .dash-btn.primary:hover::after {
            width: 300px;
            height: 300px;
        }

        .dash-btn.primary:hover {
            transform: translateY(-2px) translateX(0);
            box-shadow: 0 8px 30px rgba(99, 102, 241, 0.5), inset 0 1px 0 rgba(255,255,255,0.3);
        }

        .dash-main {
            flex: 1;
            padding: 44px 56px;
            overflow-y: auto;
            background: linear-gradient(180deg, #f8fafc 0%, #ffffff 65%);
            color: var(--dash-text);
        }

        .dash-header {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 28px;
            letter-spacing: -0.2px;
            color: #0f172a;
        }

        .post-list-card {
            background: #ffffff;
            border-radius: 16px;
            border: 1px solid #e2e8f0;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(15, 23, 42, 0.08);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            animation: fadeIn 0.5s ease;
        }

        .post-list-card:hover {
            box-shadow: 0 12px 40px rgba(99, 102, 241, 0.15);
            border-color: #a5b4fc;
            transform: translateY(-4px);
        }

        .dash-post-item {
            padding: 22px 26px;
            border-bottom: 1px solid #f1f5f9;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .dash-post-item:hover {
            background: linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%);
        }

        .dash-post-item:last-child {
            border-bottom: none;
        }

        .dpi-title {
            font-size: 15px;
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 5px;
        }

        .dpi-meta {
            font-size: 12px;
            color: #64748b;
            font-family: 'Inter', 'Noto Sans SC', sans-serif;
        }

        #editor-view {
            background: var(--word-bg);
            color: var(--word-text);
            flex-direction: column;
        }

        .word-topbar {
            background: linear-gradient(135deg, #4f46e5 0%, #2563eb 100%);
            color: white;
            height: 54px;
            display: flex;
            align-items: center;
            padding: 0 20px;
            justify-content: space-between;
            box-shadow: 0 6px 16px rgba(37, 99, 235, 0.25);
        }

        .word-back-btn {
            background: rgba(255,255,255,0.15);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-weight: 600;
            transition: all 0.2s ease;
        }

        .word-back-btn:hover {
            background: rgba(255,255,255,0.25);
            transform: translateX(-2px);
        }

        .word-ribbon {
            background: #ffffff;
            border-bottom: 1px solid #e2e8f0;
            padding: 14px 20px;
            display: flex;
            gap: 10px;
            box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04);
        }

        .word-rib-btn {
            border: 1px solid #e2e8f0;
            background: #f8fafc;
            padding: 10px 14px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 5px;
            color: #0f172a;
            transition: all 0.2s ease;
            position: relative;
            font-weight: 600;
        }
        
        .word-rib-btn span:first-child {
            font-size: 18px;
        }

        .word-rib-btn:hover {
            background: #4f46e5;
            border-color: #4338ca;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(79, 70, 229, 0.35);
        }
        
        .word-rib-btn:active {
            transform: translateY(0);
        }

        .word-workspace {
            flex: 1;
            display: flex;
            overflow: hidden;
        }

        .word-canvas {
            flex: 1;
            background: linear-gradient(135deg, #eef2f7 0%, #ffffff 100%);
            padding: 36px;
            overflow-y: auto;
            display: flex;
            justify-content: center;
            gap: 24px;
            align-items: flex-start;
            max-width: 100%;
        }

        .word-paper {
            width: 800px;
            max-width: 800px;
            flex-shrink: 0;
            min-height: calc(100vh - 200px);
            background: white;
            box-shadow: 0 16px 36px rgba(15, 23, 42, 0.12), 0 2px 6px rgba(15, 23, 42, 0.08);
            padding: 56px 72px;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            border-radius: 16px;
            position: relative;
        }
        

        .meta-panel {
            width: 360px;
            min-width: 360px;
            max-width: 360px;
            flex-shrink: 0;
            background: #ffffff;
            box-shadow: 0 12px 24px rgba(15, 23, 42, 0.1);
            padding: 26px;
            box-sizing: border-box;
            border-radius: 16px;
            max-height: calc(100vh - 200px);
            overflow-y: auto;
            position: sticky;
            top: 30px;
            border: 1px solid #e2e8f0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .meta-panel:hover {
            box-shadow: 0 16px 32px rgba(15, 23, 42, 0.14);
            border-color: #cbd5f5;
        }

        #comments-panel {
            width: 360px !important;
            min-width: 360px !important;
            max-width: 360px !important;
            flex-shrink: 0 !important;
            background: white !important;
            box-shadow: 0 12px 24px rgba(15, 23, 42, 0.1) !important;
            padding: 24px !important;
            box-sizing: border-box !important;
            border-radius: 16px !important;
            max-height: calc(100vh - 200px) !important;
            overflow-y: auto !important;
            position: sticky !important;
            top: 30px !important;
            border: 1px solid #e2e8f0 !important;
            border-left: 4px solid #f59e0b !important;
            transition: all 0.3s ease !important;
        }

        #comments-panel.show {
            display: block !important;
        }

        #comments-panel.hide {
            display: none !important;
        }

        .meta-panel h3 {
            margin: 0 0 22px 0;
            font-size: 16px;
            font-weight: 700;
            color: #1a1a1a;
            border-bottom: 2px solid #4a90e2;
            padding-bottom: 12px;
            letter-spacing: 0.5px;
        }

        .meta-section {
            margin-bottom: 22px;
        }

        .meta-section label {
            display: block;
            font-size: 12px;
            color: #666;
            margin-bottom: 8px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .meta-input {
            width: 100%;
            padding: 12px 14px;
            border: 1.5px solid #dfe3ec;
            border-radius: 8px;
            font-size: 13px;
            box-sizing: border-box;
            font-family: var(--font-main);
            background: #fafbfc;
            color: #2c3e50;
            transition: all 0.2s ease;
        }

        .meta-input:focus {
            outline: none;
            border-color: #4a90e2;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.1);
        }

        .meta-input:hover {
            border-color: #c5d0e0;
        }

        .tag-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 12px;
            min-height: 44px;
            padding: 12px 14px;
            border: 1.5px solid #dfe3ec;
            border-radius: 8px;
            background: linear-gradient(135deg, #fafbfc 0%, #f5f7fb 100%);
            align-content: flex-start;
        }

        .tag-item {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(135deg, #4a90e2 0%, #2e5bad 100%);
            color: white;
            padding: 7px 14px;
            border-radius: 18px;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 2px 6px rgba(74, 144, 226, 0.25);
            transition: all 0.2s ease;
        }

        .tag-item:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 10px rgba(74, 144, 226, 0.35);
        }

        .tag-remove {
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            opacity: 0.8;
        }

        .tag-remove:hover {
            opacity: 1;
        }

        .tag-input-row {
            display: flex;
            gap: 8px;
        }

        .tag-input-row input {
            flex: 1;
            padding: 10px 12px;
            border: 1.5px solid #dfe3ec;
            border-radius: 8px;
            font-size: 13px;
            background: #fafbfc;
            color: #2c3e50;
            transition: all 0.2s ease;
        }

        .tag-input-row input:focus {
            outline: none;
            border-color: #4a90e2;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.1);
        }

        .tag-input-row button {
            padding: 10px 16px;
            background: linear-gradient(135deg, #4a90e2 0%, #2e5bad 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(74, 144, 226, 0.2);
        }

        .tag-input-row button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(74, 144, 226, 0.35);
        }

        .tag-input-row button:active {
            transform: translateY(0);
        }

        .meta-checkbox {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 10px;
            padding: 10px 12px;
            border-radius: 8px;
            background: #f5f7fb;
            transition: all 0.2s ease;
        }

        .meta-checkbox:hover {
            background: #eff3fb;
        }

        .meta-checkbox input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            accent-color: #4a90e2;
        }

        .meta-checkbox label {
            margin: 0;
            cursor: pointer;
            font-size: 13px;
            color: #2c3e50;
            font-weight: 500;
        }

        .wp-title {
            font-family: 'Sitka Small', serif;
            font-size: 36px;
            font-weight: 800;
            background: linear-gradient(135deg, #1a1a1a 0%, #333333 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            border-bottom: 2px solid #e8eef5;
            padding-bottom: 22px;
            margin-bottom: 32px;
            letter-spacing: -0.5px;
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15, 23, 42, 0.7);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }

        .modal-card {
            background: white;
            color: #0f172a;
            width: 500px;
            padding: 30px;
            border-radius: 16px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 20px 60px rgba(15, 23, 42, 0.3);
        }

        .modal-card h2 {
            color: #0f172a;
            font-weight: 700;
        }

        .modal-card label {
            color: #475569;
            font-weight: 500;
            font-size: 14px;
        }

        .modal-card input {
            width: 100%;
            padding: 12px;
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            color: #0f172a;
            border-radius: 8px;
            margin-top: 8px;
            margin-bottom: 20px;
            box-sizing: border-box;
            transition: all 0.2s;
        }

        .modal-card input:focus {
            outline: none;
            border-color: #8b5cf6;
            background: white;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
        }

        .modal-card button {
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            border: none;
        }

        .btn-confirm {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            color: white;
            border: none;
        }

        .btn-cancel {
            background: #f1f5f9;
            color: #475569;
            border: 1px solid #cbd5e1;
            margin-right: 10px;
        }

        .btn-cancel:hover {
            background: #e2e8f0;
            border-color: #94a3b8;
        }

        .btn-confirm:hover {
            background: linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%);
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
        }

        #editor-textarea {
            width: 100%;
            height: 100%;
            min-height: 600px;
            border: 1.5px solid #dfe3ec;
            resize: none;
            outline: none;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 15px;
            line-height: 1.8;
            color: #2c3e50;
            padding: 20px;
            tab-size: 4;
            border-radius: 12px;
            background: #ffffff;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
            transition: all 0.2s ease;
        }
        
        #editor-textarea:focus {
            border-color: #4a90e2;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.02), 0 0 0 3px rgba(74, 144, 226, 0.1);
        }
        
        #editor-textarea::selection {
            background: #4f46e5;
            color: #ffffff;
        }
        
        #editor-textarea::-moz-selection {
            background: #4f46e5;
            color: #ffffff;
        }
        
        .pending-comment-card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-left: 4px solid #f59e0b;
            border-radius: 12px;
            padding: 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
            margin-bottom: 16px;
            overflow: hidden;
        }
        
        .pending-comment-card:hover {
            box-shadow: 0 8px 24px rgba(245, 158, 11, 0.15);
            border-left-color: #f97316;
            transform: translateY(-2px);
        }
        
        .comment-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 20px;
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border-bottom: 1px solid #fde047;
        }
        
        .comment-number {
            font-size: 14px;
            font-weight: 700;
            color: #92400e;
            background: #fbbf24;
            padding: 4px 12px;
            border-radius: 20px;
        }
        
        .pending-select {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }
        
        .comment-post-title {
            font-size: 14px;
            color: #6366f1;
            margin: 0;
            padding: 16px 20px 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .comment-user-info {
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 0 20px 16px;
        }
        
        .user-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            font-weight: 700;
            flex-shrink: 0;
            box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3);
        }
        
        .user-details {
            flex: 1;
            min-width: 0;
        }
        
        .comment-meta {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 4px;
            font-size: 12px;
            color: #9ca3af;
            flex-wrap: wrap;
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        .comment-author {
            font-weight: 700;
            color: #111827;
            font-size: 16px;
            margin-bottom: 4px;
        }
        
        .comment-content-preview {
            color: #374151;
            line-height: 1.7;
            margin: 0;
            padding: 20px;
            background: #f9fafb;
            font-size: 14px;
            border-top: 1px solid #e5e7eb;
            border-bottom: 1px solid #e5e7eb;
            min-height: 60px;
        }
        
        .comment-tech-info {
            font-size: 12px;
            color: #6b7280;
            padding: 16px 20px;
            background: #fafafa;
            display: grid;
            grid-template-columns: 1fr;
            gap: 8px;
        }
        
        .tech-item {
            display: flex;
            align-items: center;
            gap: 6px;
            line-height: 1.5;
        }
        
        .tech-item strong {
            color: #374151;
            min-width: 30px;
        }
        
        .tech-ua {
            word-break: break-all;
        }
        
        .comment-actions {
            display: flex;
            gap: 10px;
            padding: 16px 20px;
            background: #ffffff;
        }
        
        .comment-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-approve {
            padding: 10px 20px;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.25);
        }
        
        .btn-approve:hover {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.35);
        }
        
        .btn-edit {
            padding: 10px 20px;
            background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(14, 165, 233, 0.25);
        }
        
        .btn-edit:hover {
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.35);
        }
        
        .btn-delete {
            padding: 10px 20px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(239, 68, 68, 0.25);
        }
        
        .btn-delete:hover {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.35);
        }
        
        .comment-tech-info {
            font-size: 12px;
            color: #9ca3af;
            margin-top: 14px;
            padding-top: 14px;
            border-top: 1px solid #e5e7eb;
            line-height: 1.6;
        }
        
        .comment-tech-info div {
            margin: 4px 0;
        }

        .pending-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 24px;
            padding: 16px 20px;
            background: white;
            border-radius: 12px;
            border: 1px solid #e5e7eb;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }

        .pending-toolbar label {
            font-size: 13px;
            color: var(--dash-text);
        }
        
        .btn-approve-bulk, .btn-delete-bulk {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        }
        
        .btn-approve-bulk {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
        }
        
        .btn-approve-bulk:hover {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
        }
        
        .btn-delete-bulk {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        
        .btn-delete-bulk:hover {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 10px rgba(239, 68, 68, 0.3);
        }

        .settings-panel {
            margin-top: 20px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
        }

        .settings-title {
            font-size: 13px;
            font-weight: 700;
            color: var(--dash-text);
            margin: 10px 0;
        }

        .settings-row {
            margin-bottom: 10px;
        }

        .settings-row input,
        .settings-row textarea {
            width: 100%;
            padding: 8px 10px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            background: rgba(0, 0, 0, 0.2);
            color: #fff;
            font-size: 12px;
            box-sizing: border-box;
        }

        .settings-row textarea {
            min-height: 60px;
            resize: vertical;
        }
    </style>
</head>
<body>
    <div id="dashboard-view" class="view-section active">
        <div class="dash-sidebar">
            <div class="dash-logo">WangScape 写作助手</div>
            <button class="dash-btn primary" onclick="openCreateModal()">+ 新建文章 (双语同步)</button>
            <button class="dash-btn" onclick="runCommand('preview')">🌍 启动实时预览</button>
            <button class="dash-btn" onclick="runCommand('deploy')">🚀 一键提交推送</button>
            <button class="dash-btn" onclick="switchView('pending-comments')">💬 未审核评论</button>
            <button class="dash-btn" onclick="switchView('history')">📊 操作历史</button>
            <button class="dash-btn" onclick="location.reload()">🔄 刷新列表</button>
            
            <div id="comment-stats-box" style="background: rgba(255,152,0,0.1); border: 1px solid rgba(255,152,0,0.3); border-radius: 12px; padding: 15px; margin-top: 20px; display: none;">
                <div style="font-size: 13px; color: #ff9800; font-weight: 600; margin-bottom: 8px;">💬 评论统计</div>
                <div style="font-size: 12px; color: var(--dash-text); line-height: 1.8;">
                    <div>待审核: <span id="pending-count" style="color: #ff9800; font-weight: 700;">0</span></div>
                    <div>总评论: <span id="total-count" style="color: var(--dash-text);">0</span></div>
                </div>
            </div>

            <div id="auth-panel" style="margin-top: 18px; padding: 12px; background: rgba(79,70,229,0.08); border: 1px solid rgba(79,70,229,0.2); border-radius: 12px;">
                <div style="font-size: 12px; color: #4f46e5; font-weight: 700; margin-bottom: 8px;">🔐 登录状态</div>
                <div id="auth-status" style="font-size: 12px; color: var(--dash-text); margin-bottom: 10px;">未登录</div>
                <div style="display:flex; gap:8px;">
                    <button id="login-btn" class="dash-btn" style="flex:1;" onclick="console.log('Login button clicked!'); openLoginModal();">登录</button>
                    <button id="logout-btn" class="dash-btn" style="flex:1; display:none;" onclick="logout()">退出</button>
                </div>
            </div>
            
            <div style="margin-top:auto; font-size:12px; color:var(--dash-text-dim);">
                <span>系统状态: 在线</span><br>
                v3.0 Go Edition
            </div>
        </div>
        <div class="dash-main">
            <h1 class="dash-header">最新博文内容</h1>
            <div id="dash-post-list" class="post-list-card"></div>
        </div>
    </div>

    <div id="pending-comments-view" class="view-section">
        <div class="dash-sidebar">
            <div class="dash-logo">未审核评论</div>
            <button class="dash-btn" onclick="switchView('dashboard')">← 返回主面板</button>
            <button class="dash-btn" onclick="loadPendingComments()">🔄 刷新</button>
            <button class="dash-btn" onclick="exportCommentsCsv()">📥 导出CSV</button>

            <div id="auth-panel-pending" style="margin: 12px 0 8px; padding: 12px; background: rgba(79,70,229,0.08); border: 1px solid rgba(79,70,229,0.2); border-radius: 12px;">
                <div style="font-size: 12px; color: #4f46e5; font-weight: 700; margin-bottom: 8px;">🔐 登录状态</div>
                <div id="auth-status-pending" style="font-size: 12px; color: var(--dash-text); margin-bottom: 10px;">未登录</div>
                <div style="display:flex; gap:8px;">
                    <button id="login-btn-pending" class="dash-btn" style="flex:1;" onclick="console.log('Login button clicked!'); openLoginModal();">登录</button>
                    <button id="logout-btn-pending" class="dash-btn" style="flex:1; display:none;" onclick="logout()">退出</button>
                </div>
            </div>

            <div class="settings-panel">
                <div class="settings-title">🔔 邮件通知</div>
                <div class="settings-row">
                    <label><input type="checkbox" id="smtp-enabled" /> 启用SMTP</label>
                </div>
                <div class="settings-row">
                    <input type="text" id="smtp-host" placeholder="SMTP Host" />
                </div>
                <div class="settings-row">
                    <input type="number" id="smtp-port" placeholder="SMTP Port" />
                </div>
                <div class="settings-row">
                    <input type="text" id="smtp-user" placeholder="SMTP 用户名" />
                </div>
                <div class="settings-row">
                    <input type="password" id="smtp-pass" placeholder="SMTP 密码" />
                </div>
                <div class="settings-row">
                    <input type="text" id="smtp-from" placeholder="发件人地址" />
                </div>
                <div class="settings-row">
                    <input type="text" id="smtp-to" placeholder="收件人(逗号分隔)" />
                </div>
                <div class="settings-row">
                    <label><input type="checkbox" id="notify-pending" /> 新评论提醒</label>
                </div>
                <div class="settings-row">
                    <button class="dash-btn" onclick="testMailConnection()" style="background:#3b82f6;">✉️ 发送测试邮件</button>
                </div>

                <div class="settings-title">⛔ 黑名单</div>
                <div class="settings-row">
                    <textarea id="blacklist-ips" placeholder="IP列表，一行一个"></textarea>
                </div>
                <div class="settings-row">
                    <textarea id="blacklist-words" placeholder="关键词列表，一行一个"></textarea>
                </div>

                <button class="dash-btn" onclick="saveCommentSettings()">💾 保存设置</button>
            </div>
            
            <div style="margin-top:auto; font-size:12px; color:var(--dash-text-dim);">
                <span id="pending-total-count">加载中...</span>
            </div>
        </div>
        <div class="dash-main">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h1 class="dash-header" style="margin: 0;">📬 待审核评论</h1>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span id="pending-total-count-header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; box-shadow: 0 2px 8px rgba(102,126,234,0.3);">0 条待审核</span>
                    <button onclick="loadPendingComments()" style="background: white; border: 1px solid #e5e7eb; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.2s;" onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='white'">🔄 刷新</button>
                </div>
            </div>
            
            <div class="pending-toolbar">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; padding: 8px 12px; background: #f9fafb; border-radius: 8px; transition: all 0.2s;" onmouseover="this.style.background='#f3f4f6'" onmouseout="this.style.background='#f9fafb'">
                        <input type="checkbox" id="pending-select-all" onchange="toggleSelectAllPending()" style="width: 16px; height: 16px; cursor: pointer;" /> 
                        <span style="font-weight: 500; font-size: 14px;">全选</span>
                    </label>
                    <span id="selected-count" style="color: #6b7280; font-size: 13px; margin-left: 5px;">未选择</span>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button class="btn-approve-bulk" onclick="bulkApprovePending()">✅ 批量批准</button>
                    <button class="btn-delete-bulk" onclick="bulkDeletePending()">🗑 批量删除</button>
                </div>
            </div>
            
            <div id="pending-comments-list" style="display:flex; flex-direction:column; gap:16px;"></div>
        </div>
    </div>

    <div id="history-view" class="view-section">
        <div class="dash-sidebar">
            <div class="dash-logo">📊 操作历史</div>
            <button class="dash-btn" onclick="switchView('dashboard')">← 返回主面板</button>
            <button class="dash-btn" onclick="loadOperationHistory()">🔄 刷新</button>
            <button class="dash-btn" onclick="exportHistoryCsv()">📥 导出CSV</button>
            
            <div class="settings-panel">
                <div class="settings-title">📁 筛选类型</div>
                <label style="display:block; margin:8px 0;">
                    <input type="checkbox" id="filter-comments" checked onchange="loadOperationHistory()" /> 评论操作
                </label>
                <label style="display:block; margin:8px 0;">
                    <input type="checkbox" id="filter-posts" checked onchange="loadOperationHistory()" /> 文章操作
                </label>
            </div>

            <div class="settings-panel">
                <div class="settings-title">🕐 日期范围</div>
                <input type="date" id="history-date-from" style="width:100%; padding:8px; margin:5px 0; border:1px solid #d1d5db; border-radius:6px;" onchange="loadOperationHistory()" />
                <input type="date" id="history-date-to" style="width:100%; padding:8px; margin:5px 0; border:1px solid #d1d5db; border-radius:6px;" onchange="loadOperationHistory()" />
            </div>
        </div>
        <div class="dash-main">
            <h1 class="dash-header">操作历史记录</h1>
            <div class="history-stats" style="display:grid; grid-template-columns:repeat(3,1fr); gap:15px; margin-bottom:20px;">
                <div style="background:rgba(79,70,229,0.1); padding:15px; border-radius:8px; border-left:4px solid #4f46e5;">
                    <div style="font-size:12px; color:#6366f1; font-weight:600; margin-bottom:5px;">总操作数</div>
                    <div style="font-size:24px; font-weight:700; color:#4f46e5;" id="total-ops">0</div>
                </div>
                <div style="background:rgba(34,197,94,0.1); padding:15px; border-radius:8px; border-left:4px solid #22c55e;">
                    <div style="font-size:12px; color:#16a34a; font-weight:600; margin-bottom:5px;">评论操作</div>
                    <div style="font-size:24px; font-weight:700; color:#22c55e;" id="total-comment-ops">0</div>
                </div>
                <div style="background:rgba(59,130,246,0.1); padding:15px; border-radius:8px; border-left:4px solid #3b82f6;">
                    <div style="font-size:12px; color:#1d4ed8; font-weight:600; margin-bottom:5px;">文章操作</div>
                    <div style="font-size:24px; font-weight:700; color:#3b82f6;" id="total-post-ops">0</div>
                </div>
            </div>
            <div id="history-list" style="display:flex; flex-direction:column; gap:12px;"></div>
        </div>
    </div>

    <div id="editor-view" class="view-section">
        <div class="word-topbar">
            <div style="display:flex; align-items:center; gap:15px;">
                <button class="word-back-btn" onclick="switchView('dashboard')">← 返回主面板</button>
                <strong style="font-size:16px;">WangScape 写作器</strong>
                <span id="current-doc-name" style="opacity:0.9; font-size:14px; font-weight:500;"></span>
            </div>
            <div style="display:flex; align-items:center; gap:20px;">
                <span id="word-count" style="font-size:13px; color:rgba(255,255,255,0.9);">字数: 0</span>
                <span id="save-status" style="font-size:13px; color:rgba(255,255,255,0.8);"></span>
            </div>
        </div>
        <div class="word-ribbon">
            <button class="word-rib-btn" onclick="saveDocument()" title="保存文档 (Ctrl+S)">
                <span>💾</span>
                <span>保存</span>
            </button>
            <button class="word-rib-btn" onclick="toggleMetadataPanel()" title="编辑文章信息">
                <span>📋</span>
                <span>元数据</span>
            </button>
            <button class="word-rib-btn" onclick="switchCommentView()" title="管理评论">
                <span>💬</span>
                <span>评论</span>
            </button>
            <div style="width:1px; height:30px; background:#e0e0e0; margin:0 5px;"></div>
            <button class="word-rib-btn" onclick="insertCodeBlock()" title="插入代码块">
                <span>💻</span>
                <span>代码</span>
            </button>
            <button class="word-rib-btn" onclick="insertImage()" title="插入图片">
                <span>🖼</span>
                <span>图片</span>
            </button>
            <button class="word-rib-btn" onclick="insertTable()" title="插入表格">
                <span>📊</span>
                <span>表格</span>
            </button>
            <div style="width:1px; height:30px; background:#e0e0e0; margin:0 5px;"></div>
            <button class="word-rib-btn" onclick="runCommand('preview')" title="实时预览">
                <span>👁</span>
                <span>预览</span>
            </button>
            <button class="word-rib-btn" onclick="runCommand('deploy')" title="发布到网站">
                <span>🚀</span>
                <span>发布</span>
            </button>
        </div>
        <div class="word-workspace">
            <div class="word-canvas">
                <div class="word-paper" id="paper-content">
                    <div style="text-align:center; color:#999; margin-top:100px;">
                        请选择左侧文章进行编辑
                    </div>
                </div>
                <div class="meta-panel" id="meta-panel" style="display:none;">
                    <h3>📋 文章信息</h3>
                    
                    <div class="meta-section">
                        <label>标题 (Title)</label>
                        <input type="text" class="meta-input" id="title-input" placeholder="文章标题" />
                    </div>

                    <div class="meta-section">
                        <label>日期 (Date)</label>
                        <input type="datetime-local" class="meta-input" id="date-input" />
                    </div>

                    <div class="meta-section">
                        <label>分类 (Categories)</label>
                        <div class="tag-container" id="categories-container"></div>
                        <div class="tag-input-row">
                            <input type="text" id="category-input" placeholder="添加分类..." onkeypress="if(event.key==='Enter'){addCategory();event.preventDefault();}" />
                            <button onclick="addCategory()">添加</button>
                        </div>
                    </div>

                    <div class="meta-section">
                        <label>标签 (Tags)</label>
                        <div class="tag-container" id="tags-container"></div>
                        <div class="tag-input-row">
                            <input type="text" id="tag-input" placeholder="添加标签..." onkeypress="if(event.key==='Enter'){addTag();event.preventDefault();}" />
                            <button onclick="addTag()">添加</button>
                        </div>
                    </div>

                    <div class="meta-section">
                        <label>描述 (Description)</label>
                        <textarea class="meta-input" id="description-input" rows="3" placeholder="文章简介..." style="resize: vertical; min-height: 60px;"></textarea>
                    </div>

                    <div class="meta-section">
                        <label>封面图片 URL (Image)</label>
                        <input type="text" class="meta-input" id="image-input" placeholder="/img/cover.jpg" />
                    </div>

                    <div class="meta-section">
                        <label>许可证 (License)</label>
                        <input type="text" class="meta-input" id="license-input" placeholder="CC BY-SA 4.0" />
                    </div>

                    <div class="meta-section">
                        <div class="meta-checkbox">
                            <input type="checkbox" id="draft-checkbox" />
                            <label for="draft-checkbox">📝 草稿状态</label>
                        </div>
                        <div class="meta-checkbox">
                            <input type="checkbox" id="math-checkbox" />
                            <label for="math-checkbox">📐 启用数学公式</label>
                        </div>
                        <div class="meta-checkbox">
                            <input type="checkbox" id="comments-checkbox" />
                            <label for="comments-checkbox">💬 允许评论</label>
                        </div>
                        <div class="meta-checkbox">
                            <input type="checkbox" id="hidden-checkbox" />
                            <label for="hidden-checkbox">🔒 隐藏文章</label>
                        </div>
                        <div class="meta-checkbox">
                            <input type="checkbox" id="pinned-checkbox" />
                            <label for="pinned-checkbox">📌 置顶文章</label>
                        </div>
                    </div>

                    <button class="dash-btn primary" style="width:100%; margin-top:10px;" onclick="applyMetadata()">💾 应用更改</button>
                </div>

                <div id="comments-panel" class="meta-panel hide">
                    <h3>💬 评论管理</h3>
                    <div id="comments-list" style="max-height: 500px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="create-modal">
        <div class="modal-card">
            <h2 style="margin-top:0">创建新文章</h2>
            <label>中文标题</label>
            <input type="text" id="postTitle" placeholder="例如：冬日随笔">
            <label>分类（英文）</label>
            <input type="text" id="postCat" placeholder="Life, Code">
            <p style="font-size:12px; color:var(--dash-text-dim)">* 系统将自动翻译为英文并创建双语版本。</p>
            <div style="text-align:right">
                <button class="btn-cancel" onclick="closeCreateModal()">取消</button>
                <button class="btn-confirm" onclick="createPost()">创建</button>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="login-modal" style="display:none;">
        <div class="modal-card">
            <h2 style="margin-top:0">管理员登录</h2>
            <label>用户名</label>
            <input type="text" id="login-username" placeholder="admin">
            <label>密码</label>
            <input type="password" id="login-password" placeholder="请输入密码">
            <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:10px;">
                <button class="btn-cancel" onclick="closeLoginModal()">取消</button>
                <button class="btn-confirm" onclick="performLogin()">登录</button>
            </div>
            <p id="login-hint" style="font-size:12px; color:#64748b; margin-top:8px; display:none;"></p>
        </div>
    </div>

    <script>
        let postsData = [];
        let currentDocPath = '';
        let commentStatsData = null;
        let authToken = localStorage.getItem('auth_token') || '';

        function setAuthToken(token) {
            authToken = token || '';
            if (authToken) {
                localStorage.setItem('auth_token', authToken);
            } else {
                localStorage.removeItem('auth_token');
            }
            updateAuthStatus();
        }

        function getAuthHeaders() {
            if (!authToken) return {};
            return { 'Authorization': 'Bearer ' + authToken };
        }

        async function authFetch(url, options = {}) {
            const headers = Object.assign({}, options.headers || {}, getAuthHeaders());
            console.log('[DEBUG] authFetch:', { url, headers, authToken: authToken ? '***' : 'NONE' });
            const response = await fetch(url, Object.assign({}, options, { headers }));
            console.log('[DEBUG] Response status:', response.status);
            if (response.status === 401) {
                openLoginModal('需要登录才能继续操作');
            }
            return response;
        }

        function openLoginModal(message) {
            console.log('openLoginModal called with message:', message);
            const modal = document.getElementById('login-modal');
            const hint = document.getElementById('login-hint');
            
            if (!modal) {
                console.error('login-modal element not found!');
                alert('错误：登录窗口未找到，请刷新页面重试');
                return;
            }
            
            console.log('Modal element found, displaying...');
            
            if (message) {
                hint.textContent = message;
                hint.style.display = 'block';
            } else {
                hint.style.display = 'none';
            }
            modal.style.display = 'flex';
            
            console.log('Modal display set to flex');
        }

        function closeLoginModal() {
            const modal = document.getElementById('login-modal');
            if (modal) {
                modal.style.display = 'none';
            }
        }

        async function performLogin() {
            const username = document.getElementById('login-username').value.trim();
            const password = document.getElementById('login-password').value;
            if (!username || !password) {
                openLoginModal('请输入用户名和密码');
                return;
            }
            
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                if (!res.ok) {
                    const data = await res.json().catch(() => ({ message: '服务器错误' }));
                    openLoginModal(data.message || '登录失败: ' + res.status);
                    console.error('登录失败:', res.status, data);
                    return;
                }
                
                const data = await res.json();
                console.log('登录响应:', data);
                
                if (data && data.access_token) {
                    setAuthToken(data.access_token);
                    closeLoginModal();
                    updateAuthStatus();
                    alert('✅ 登录成功！');
                } else {
                    openLoginModal(data.message || '登录失败：未返回令牌');
                }
            } catch (e) {
                console.error('登录错误:', e);
                openLoginModal('网络错误: ' + e.message);
            }
        }

        function logout() {
            setAuthToken('');
        }

        function updateAuthStatus() {
            const statusText = authToken ? '已登录' : '未登录';
            const statusEl = document.getElementById('auth-status');
            const statusElPending = document.getElementById('auth-status-pending');
            if (statusEl) statusEl.textContent = statusText;
            if (statusElPending) statusElPending.textContent = statusText;
            
            // 根据登录状态切换按钮显示
            const loginBtn = document.getElementById('login-btn');
            const logoutBtn = document.getElementById('logout-btn');
            const loginBtnPending = document.getElementById('login-btn-pending');
            const logoutBtnPending = document.getElementById('logout-btn-pending');
            
            if (authToken) {
                // 已登录：隐藏登录按钮，显示退出按钮
                if (loginBtn) loginBtn.style.display = 'none';
                if (logoutBtn) logoutBtn.style.display = 'block';
                if (loginBtnPending) loginBtnPending.style.display = 'none';
                if (logoutBtnPending) logoutBtnPending.style.display = 'block';
            } else {
                // 未登录：显示登录按钮，隐藏退出按钮
                if (loginBtn) loginBtn.style.display = 'block';
                if (logoutBtn) logoutBtn.style.display = 'none';
                if (loginBtnPending) loginBtnPending.style.display = 'block';
                if (logoutBtnPending) logoutBtnPending.style.display = 'none';
            }
        }

        function switchView(view) {
            document.querySelectorAll('.view-section').forEach(e => e.classList.remove('active'));
            document.getElementById(view + '-view').classList.add('active');
            if (view === 'dashboard') {
                fetchPosts();
                fetchCommentStats();
            } else if (view === 'pending-comments') {
                loadPendingComments();
                loadCommentSettings();
            } else if (view === 'history') {
                loadOperationHistory();
            }
        }

        async function fetchCommentStats() {
            try {
                const res = await authFetch('/api/comment_stats');
                const data = await res.json();
                if (data.success && data.data) {
                    commentStatsData = data.data;
                    updateCommentStatsDisplay();
                    renderDashboardList();
                }
            } catch(e) {
                console.error('获取评论统计失败:', e);
            }
        }

        function updateCommentStatsDisplay() {
            if (!commentStatsData) return;
            
            const statsBox = document.getElementById('comment-stats-box');
            const pendingCount = document.getElementById('pending-count');
            const totalCount = document.getElementById('total-count');
            
            if (commentStatsData.total_pending > 0 || commentStatsData.total_comments > 0) {
                statsBox.style.display = 'block';
                pendingCount.textContent = commentStatsData.total_pending;
                totalCount.textContent = commentStatsData.total_comments;
            } else {
                statsBox.style.display = 'none';
            }
        }

        async function fetchPosts() {
            const res = await fetch('/api/posts');
            postsData = await res.json();
            renderDashboardList();
        }

        function renderDashboardList() {
            const list = document.getElementById('dash-post-list');
            if (postsData.length === 0) {
                list.innerHTML = '<div style="padding:40px; text-align:center; color:#555;">暂无文章</div>';
                return;
            }
            
            // 按路径分组（中英文版本）
            const grouped = {};
            postsData.forEach(p => {
                // 提取基础名称（去掉 zh-cn 或 en 前缀）
                const baseName = p.path.replace(/content\/(zh-cn|en)\/post\//, '');
                if (!grouped[baseName]) {
                    grouped[baseName] = { zh: null, en: null };
                }
                if (p.lang === 'zh-cn' || p.lang === 'zh') {
                    grouped[baseName].zh = p;
                } else if (p.lang === 'en') {
                    grouped[baseName].en = p;
                }
            });
            
            list.innerHTML = Object.entries(grouped).map(([baseName, versions]) => {
                const primaryVersion = versions.zh || versions.en;
                if (!primaryVersion) return '';
                
                const escapedPath = primaryVersion.path.replace(/\\/g, '\\\\');
                let html = '<div class="dash-post-item">' +
                    '<div onclick="openEditor(\'' + escapedPath + '\', \'' + primaryVersion.title.replace(/'/g, "\\'") + '\', \'' + primaryVersion.date + '\')" style="flex:1; cursor:pointer; display:flex; flex-direction:column; gap:4px;">' +
                    '<div style="display:flex; align-items:center; gap:10px;">' +
                    '<div class="dpi-title">' + primaryVersion.title + '</div>' +
                    '<span style="font-size:10px; padding:2px 6px; border-radius:4px; background:' + primaryVersion.status_color + '20; color:' + primaryVersion.status_color + ';">' +
                    primaryVersion.status +
                    '</span>';
                
                // 显示版本标签
                if (versions.zh && versions.en) {
                    html += '<span style="font-size:9px; padding:2px 4px; background:#4a90e2; color:#fff; border-radius:3px;">中英双版</span>';
                } else if (versions.zh) {
                    html += '<span style="font-size:9px; padding:2px 4px; background:#ff7f50; color:#fff; border-radius:3px;">中文版</span>';
                } else if (versions.en) {
                    html += '<span style="font-size:9px; padding:2px 4px; background:#50c878; color:#fff; border-radius:3px;">英文版</span>';
                }
                
                // 显示置顶标识
                if (primaryVersion.pinned) {
                    html += '<span style="font-size:9px; padding:2px 4px; background:#ff4444; color:#fff; border-radius:3px; margin-left:4px;">📌 置顶</span>';
                }
                
                // 显示评论统计
                if (commentStatsData && commentStatsData.post_stats) {
                    const stats = commentStatsData.post_stats[primaryVersion.path];
                    if (stats && stats.total > 0) {
                        const pendingBadge = stats.pending > 0 ? 
                            '<span style="font-size:9px; padding:2px 4px; background:#ff9800; color:#fff; border-radius:3px; margin-left:4px;">' + stats.pending + ' 待审</span>' : '';
                        html += '<span style="font-size:9px; padding:2px 4px; background:#9e9e9e; color:#fff; border-radius:3px; margin-left:4px;">💬 ' + stats.total + '</span>' + pendingBadge;
                    }
                }
                
                html += '</div>' +
                    '<div class="dpi-meta">' + primaryVersion.date + ' · ' + primaryVersion.path + '</div>' +
                    '</div>' +
                    '<div style="display:flex; gap:8px; align-items:center;">';
                
                // 显示切换按钮
                if (versions.zh && versions.en) {
                    const zhPath = versions.zh.path.replace(/\\/g, '\\\\');
                    const enPath = versions.en.path.replace(/\\/g, '\\\\');
                    const zhTitle = versions.zh.title.replace(/'/g, "\\'");
                    const enTitle = versions.en.title.replace(/'/g, "\\'");
                    
                        html += '<button onclick="openEditor(\'' + zhPath + '\', \'' + zhTitle + '\', \'' + versions.zh.date + '\')" style="background:#fff7ed; border:1px solid #fed7aa; color:#c2410c; padding:4px 8px; border-radius:6px; font-size:11px; cursor:pointer;">编辑中文</button>' +
                            '<button onclick="openEditor(\'' + enPath + '\', \'' + enTitle + '\', \'' + versions.en.date + '\')" style="background:#ecfdf3; border:1px solid #bbf7d0; color:#15803d; padding:4px 8px; border-radius:6px; font-size:11px; cursor:pointer;">编辑英文</button>';
                }
                
                    html += '<button onclick="deleteDocument(\'' + escapedPath + '\')" style="background:#fee2e2; border:1px solid #fecaca; color:#b91c1c; width:32px; height:32px; border-radius:8px; cursor:pointer;">🗑</button>' +
                        '<button onclick="openEditor(\'' + escapedPath + '\', \'' + primaryVersion.title.replace(/'/g, "\\'") + '\', \'' + primaryVersion.date + '\')" style="background:#eef2ff; border:1px solid #c7d2fe; color:#4338ca; width:32px; height:32px; border-radius:8px; cursor:pointer;">✎</button>' +
                        '</div>' +
                        '</div>';
                
                return html;
            }).join('');
        }

        async function openEditor(path, title, date) {
            currentDocPath = path;
            switchView('editor');
            
            // 检测当前编辑的语言版本
            const isZhCN = path.includes('zh-cn');
            const lang = isZhCN ? '中文版' : '英文版';
            const langColor = isZhCN ? '#ffa500' : '#50c878';
            
            document.getElementById('current-doc-name').textContent = title + ' (' + lang + ')';
            document.getElementById('current-doc-name').style.color = langColor;
            
            const paper = document.getElementById('paper-content');
            const metaPanel = document.getElementById('meta-panel');
            paper.innerHTML = '<div style="text-align:center; margin-top:50px; color:#888;">加载中...</div>';

            try {
                const res = await authFetch('/api/get_content?path=' + encodeURIComponent(path));
                const data = await res.json();
                
                // 解析frontmatter
                parseFrontmatter(data.content);
                
                paper.innerHTML = '<div class="wp-title">' + title + '</div>' +
                    '<div style="font-size:12px; color:#999; margin-bottom:20px;">版本: ' + lang + ' · 日期: ' + date + '</div>' +
                    '<textarea id="editor-textarea" spellcheck="false">' + data.content + '</textarea>';
                
                // 添加输入监听器
                const textarea = document.getElementById('editor-textarea');
                textarea.addEventListener('input', updateWordCount);
                textarea.addEventListener('input', function() {
                    document.getElementById('save-status').textContent = '⚠️ 未保存';
                    document.getElementById('save-status').style.color = 'rgba(255, 200, 100, 0.9)';
                });
                
                // 初始化字数统计
                updateWordCount();
                
                // 显示元数据面板
                metaPanel.style.display = 'block';
            } catch(e) {
                paper.innerHTML = '<div style="color:red">错误: ' + e + '</div>';
            }
        }

        let currentMetadata = {
            title: '',
            date: '',
            categories: [],
            tags: [],
            description: '',
            image: '',
            license: '',
            draft: false,
            math: false,
            comments: true,
            hidden: false,
            pinned: false
        };

        function parseFrontmatter(content) {
            // 提取frontmatter
            const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
            if (!fmMatch) {
                currentMetadata = { title: '', date: '', categories: [], tags: [], description: '', image: '', license: '', draft: false, math: false, comments: true, hidden: false, pinned: false };
                renderMetadata();
                return;
            }

            const fmContent = fmMatch[1];
            
            // 解析title
            const titleMatch = fmContent.match(/title:\s*["']?([^"'\n]+)["']?/);
            currentMetadata.title = titleMatch ? titleMatch[1].trim() : '';

            // 解析date
            const dateMatch = fmContent.match(/date:\s*([\w\-:+]+)/);
            if (dateMatch) {
                // 转换为datetime-local格式 (YYYY-MM-DDTHH:MM)
                const dateStr = dateMatch[1].replace(/([\d-]+)T([\d:]+).*/, '$1T$2');
                currentMetadata.date = dateStr.substring(0, 16);
            } else {
                currentMetadata.date = '';
            }
            
            // 解析categories
            const catMatch = fmContent.match(/categories:\s*\n((?:\s*-\s*.+\n)+)/);
            if (catMatch) {
                currentMetadata.categories = catMatch[1].split('\n')
                    .filter(l => l.trim().startsWith('-'))
                    .map(l => l.replace(/^\s*-\s*/, '').trim());
            } else {
                const catSingleMatch = fmContent.match(/categories:\s*\[([^\]]+)\]/);
                if (catSingleMatch) {
                    currentMetadata.categories = catSingleMatch[1].split(',').map(c => c.trim());
                } else {
                    currentMetadata.categories = [];
                }
            }

            // 解析tags
            const tagMatch = fmContent.match(/tags:\s*\n((?:\s*-\s*.+\n)+)/);
            if (tagMatch) {
                currentMetadata.tags = tagMatch[1].split('\n')
                    .filter(l => l.trim().startsWith('-'))
                    .map(l => l.replace(/^\s*-\s*/, '').trim());
            } else {
                const tagSingleMatch = fmContent.match(/tags:\s*\[([^\]]+)\]/);
                if (tagSingleMatch) {
                    currentMetadata.tags = tagSingleMatch[1].split(',').map(t => t.trim());
                } else {
                    currentMetadata.tags = [];
                }
            }

            // 解析description
            const descMatch = fmContent.match(/description:\s*["']?([^"'\n]+)["']?/);
            currentMetadata.description = descMatch ? descMatch[1].trim() : '';

            // 解析image
            const imgMatch = fmContent.match(/image:\s*["']?([^"'\n]+)["']?/);
            currentMetadata.image = imgMatch ? imgMatch[1].trim() : '';

            // 解析license
            const licenseMatch = fmContent.match(/license:\s*["']?([^"'\n]+)["']?/);
            currentMetadata.license = licenseMatch ? licenseMatch[1].trim() : '';

            // 解析draft
            const draftMatch = fmContent.match(/draft:\s*(true|false)/);
            currentMetadata.draft = draftMatch ? draftMatch[1] === 'true' : false;

            // 解析math
            const mathMatch = fmContent.match(/math:\s*(true|false)/);
            currentMetadata.math = mathMatch ? mathMatch[1] === 'true' : false;

            // 解析comments
            const commentsMatch = fmContent.match(/comments:\s*(true|false)/);
            currentMetadata.comments = commentsMatch ? commentsMatch[1] === 'true' : true;

            // 解析hidden
            const hiddenMatch = fmContent.match(/hidden:\s*(true|false)/);
            currentMetadata.hidden = hiddenMatch ? hiddenMatch[1] === 'true' : false;

            // 解析pinned
            const pinnedMatch = fmContent.match(/pinned:\s*(true|false)/);
            currentMetadata.pinned = pinnedMatch ? pinnedMatch[1] === 'true' : false;

            renderMetadata();
        }

        function renderMetadata() {
            // 渲染title和date
            document.getElementById('title-input').value = currentMetadata.title;
            document.getElementById('date-input').value = currentMetadata.date;

            // 渲染分类
            const catContainer = document.getElementById('categories-container');
            catContainer.innerHTML = currentMetadata.categories.map(cat =>
                '<span class="tag-item">' + cat + '<span class="tag-remove" onclick="removeCategory(\'' + cat + '\')">&times;</span></span>'
            ).join('');

            // 渲染标签
            const tagContainer = document.getElementById('tags-container');
            tagContainer.innerHTML = currentMetadata.tags.map(tag =>
                '<span class="tag-item">' + tag + '<span class="tag-remove" onclick="removeTag(\'' + tag + '\')">&times;</span></span>'
            ).join('');

            // 渲染其他字段
            document.getElementById('description-input').value = currentMetadata.description;
            document.getElementById('image-input').value = currentMetadata.image;
            document.getElementById('license-input').value = currentMetadata.license;
            document.getElementById('draft-checkbox').checked = currentMetadata.draft;
            document.getElementById('math-checkbox').checked = currentMetadata.math;
            document.getElementById('comments-checkbox').checked = currentMetadata.comments;
            document.getElementById('hidden-checkbox').checked = currentMetadata.hidden;
            document.getElementById('pinned-checkbox').checked = currentMetadata.pinned;
        }

        function addCategory() {
            const input = document.getElementById('category-input');
            const value = input.value.trim();
            if (value && !currentMetadata.categories.includes(value)) {
                currentMetadata.categories.push(value);
                renderMetadata();
                input.value = '';
            }
        }

        function removeCategory(cat) {
            currentMetadata.categories = currentMetadata.categories.filter(c => c !== cat);
            renderMetadata();
        }

        function addTag() {
            const input = document.getElementById('tag-input');
            const value = input.value.trim();
            if (value && !currentMetadata.tags.includes(value)) {
                currentMetadata.tags.push(value);
                renderMetadata();
                input.value = '';
            }
        }

        function removeTag(tag) {
            currentMetadata.tags = currentMetadata.tags.filter(t => t !== tag);
            renderMetadata();
        }

        function applyMetadata() {
            // 更新当前元数据
            currentMetadata.title = document.getElementById('title-input').value.trim();
            currentMetadata.date = document.getElementById('date-input').value;
            currentMetadata.description = document.getElementById('description-input').value.trim();
            currentMetadata.image = document.getElementById('image-input').value.trim();
            currentMetadata.license = document.getElementById('license-input').value.trim();
            currentMetadata.draft = document.getElementById('draft-checkbox').checked;
            currentMetadata.math = document.getElementById('math-checkbox').checked;
            currentMetadata.comments = document.getElementById('comments-checkbox').checked;
            currentMetadata.hidden = document.getElementById('hidden-checkbox').checked;
            currentMetadata.pinned = document.getElementById('pinned-checkbox').checked;
            currentMetadata.pinned = document.getElementById('pinned-checkbox').checked;

            // 获取当前文章内容
            const content = document.getElementById('editor-textarea').value;
            
            // 更新frontmatter
            const fmMatch = content.match(/^(---\n[\s\S]*?\n---\n)([\s\S]*)$/);
            if (!fmMatch) {
                alert('⚠️ 未找到frontmatter，无法更新');
                return;
            }

            const oldFm = fmMatch[1];
            const bodyContent = fmMatch[2];
            
            // 构建新的frontmatter
            let newFm = oldFm;
            
            // 更新title
            if (currentMetadata.title) {
                newFm = newFm.replace(/title:\s*["']?[^"'\n]+["']?/, 'title: "' + currentMetadata.title.replace(/"/g, '\\"') + '"');
            }

            // 更新date (转换为Hugo格式)
            if (currentMetadata.date) {
                const hugoDate = currentMetadata.date + ':00+08:00';
                newFm = newFm.replace(/date:\s*[\w\-:+]+/, 'date: ' + hugoDate);
            }
            
            // 更新categories
            if (currentMetadata.categories.length > 0) {
                const catYaml = 'categories:\n' + currentMetadata.categories.map(c => '    - ' + c.replace(/"/g, '\\"')).join('\n');
                newFm = newFm.replace(/categories:.*?(?=\n[a-z]|\n---)/s, catYaml);
                if (!newFm.includes('categories:')) {
                    newFm = newFm.replace(/---\n/, '---\n' + catYaml + '\n');
                }
            } else {
                newFm = newFm.replace(/categories:.*?(?=\n[a-z]|\n---)/s, '');
            }

            // 更新tags
            if (currentMetadata.tags.length > 0) {
                const tagYaml = 'tags:\n' + currentMetadata.tags.map(t => '    - ' + t.replace(/"/g, '\\"')).join('\n');
                newFm = newFm.replace(/tags:.*?(?=\n[a-z]|\n---)/s, tagYaml);
                if (!newFm.includes('tags:')) {
                    newFm = newFm.replace(/---\n/, '---\n' + tagYaml + '\n');
                }
            } else {
                newFm = newFm.replace(/tags:.*?(?=\n[a-z]|\n---)/s, '');
            }

            // 更新description
            if (currentMetadata.description) {
                newFm = newFm.replace(/description:.*?\n/, 'description: "' + currentMetadata.description.replace(/"/g, '\\"') + '"\n');
                if (!newFm.includes('description:')) {
                    newFm = newFm.replace(/---\n/, '---\ndescription: "' + currentMetadata.description.replace(/"/g, '\\"') + '"\n');
                }
            }

            // 更新image
            if (currentMetadata.image) {
                newFm = newFm.replace(/image:.*?\n/, 'image: "' + currentMetadata.image.replace(/"/g, '\\"') + '"\n');
                if (!newFm.includes('image:')) {
                    newFm = newFm.replace(/---\n/, '---\nimage: "' + currentMetadata.image.replace(/"/g, '\\"') + '"\n');
                }
            }

            // 更新draft
            newFm = newFm.replace(/draft:.*?\n/, 'draft: ' + currentMetadata.draft + '\n');
            if (!newFm.includes('draft:')) {
                newFm = newFm.replace(/---\n/, '---\ndraft: ' + currentMetadata.draft + '\n');
            }

            // 更新license
            if (currentMetadata.license) {
                newFm = newFm.replace(/license:.*?\n/, 'license: ' + currentMetadata.license + '\n');
                if (!newFm.includes('license:')) {
                    newFm = newFm.replace(/---\n/, '---\nlicense: ' + currentMetadata.license + '\n');
                }
            }

            // 更新math
            newFm = newFm.replace(/math:.*?\n/, 'math: ' + currentMetadata.math + '\n');
            if (!newFm.includes('math:')) {
                newFm = newFm.replace(/---\n/, '---\nmath: ' + currentMetadata.math + '\n');
            }

            // 更新comments
            newFm = newFm.replace(/comments:.*?\n/, 'comments: ' + currentMetadata.comments + '\n');
            if (!newFm.includes('comments:')) {
                newFm = newFm.replace(/---\n/, '---\ncomments: ' + currentMetadata.comments + '\n');
            }

            // 更新hidden
            newFm = newFm.replace(/hidden:.*?\n/, 'hidden: ' + currentMetadata.hidden + '\n');
            if (!newFm.includes('hidden:')) {
                newFm = newFm.replace(/---\n/, '---\nhidden: ' + currentMetadata.hidden + '\n');
            }

            // 更新pinned
            newFm = newFm.replace(/pinned:.*?\n/, 'pinned: ' + currentMetadata.pinned + '\n');
            if (!newFm.includes('pinned:')) {
                newFm = newFm.replace(/---\n/, '---\npinned: ' + currentMetadata.pinned + '\n');
            }

            // 更新编辑器内容
            document.getElementById('editor-textarea').value = newFm + bodyContent;
            
            alert('✅ 元数据已应用到编辑器，请点击保存按钮保存文件');
        }

        async function saveDocument() {
            if(!currentDocPath) return;
            const content = document.getElementById('editor-textarea').value;
            const statusEl = document.getElementById('save-status');
            statusEl.textContent = "💾 保存中...";
            statusEl.style.color = "#ffa500";

            try {
                const res = await authFetch('/api/save_content', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: currentDocPath, content: content })
                });
                const data = await res.json();
                if(data.success) {
                    statusEl.textContent = "✅ 已保存 " + new Date().toLocaleTimeString();
                    statusEl.style.color = "rgba(100, 255, 150, 0.9)";
                    
                    // 更新字数统计
                    updateWordCount();
                    
                    // 记录文章操作历史
                    const docName = document.getElementById('current-doc-name').textContent.trim();
                    const isNew = docName.includes('新建');
                    addOperationHistory('post', isNew ? 'create' : 'edit', currentDocPath, '字数: ' + content.length);
                    
                    // 如果是中文版本，自动同步翻译到英文版本
                    if(currentDocPath.includes('zh-cn')) {
                        statusEl.textContent = "⏳ 正在翻译英文版本...";
                        const enPath = currentDocPath.replace(/zh-cn/g, 'en');
                        
                        // 调用翻译同步接口
                        const syncRes = await authFetch('/api/sync_translate', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ 
                                zhPath: currentDocPath, 
                                enPath: enPath,
                                content: content 
                            })
                        });
                        const syncData = await syncRes.json();
                        if(syncData.success) {
                            statusEl.textContent = "✅ 已保存并同步翻译 " + new Date().toLocaleTimeString();
                        } else {
                            statusEl.textContent = "✅ 已保存（翻译失败，请手动同步）";
                        }
                    }
                    
                    setTimeout(() => statusEl.textContent = "", 3000);
                    fetchPosts();
                    return true;
                } else {
                    statusEl.textContent = "❌ 保存失败";
                    statusEl.style.color = "#ff5555";
                    alert("保存失败: " + data.message);
                    return false;
                }
            } catch(e) {
                statusEl.textContent = "❌ 网络错误";
                statusEl.style.color = "#ff5555";
                alert("网络错误: " + e);
                return false;
            }
        }

        async function deleteDocument(path) {
            if(!confirm("确定要删除这篇文章吗？操作不可恢复。")) return;
            try {
                const res = await authFetch('/api/delete_post', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                const data = await res.json();
                if(data.success) {
                    alert('✅ 文章已删除');
                    addOperationHistory('post', 'delete', path, '文章删除');
                    fetchPosts();
                } else {
                    alert("删除失败: " + data.message);
                }
            } catch(e) {
                alert("网络错误: " + e);
            }
        }

        function openCreateModal() {
            document.getElementById('create-modal').style.display = 'flex';
        }

        function closeCreateModal() {
            document.getElementById('create-modal').style.display = 'none';
        }

        async function createPost() {
            const title = document.getElementById('postTitle').value.trim();
            const cat = document.getElementById('postCat').value.trim();
            if(!title) return alert('⚠️ 请输入文章标题');

            try {
                const res = await authFetch('/api/create_sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title, categories: cat || 'Uncategorized' })
                });
                const data = await res.json();
                if(data.success) {
                    closeCreateModal();
                    document.getElementById('postTitle').value = '';
                    document.getElementById('postCat').value = '';
                    await fetchPosts();
                    alert('✅ 双语文章创建成功！\n中文版: ' + (data.data?.zh_path || '已创建') + '\n英文版: ' + (data.data?.en_path || '已创建') + '\n\n💡 提示：英文版标题已自动翻译');
                } else {
                    alert('❌ 创建失败: ' + data.message);
                }
            } catch(e) {
                alert('❌ 网络错误: ' + e);
            }
        }

        function insertCodeBlock() {
            const textarea = document.getElementById('editor-textarea');
            if(!textarea) return;

            const language = prompt('请输入代码语言 (如: javascript, python, go, bash 等):', 'javascript');
            if(language === null) return;

            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const selectedText = textarea.value.substring(start, end);
            
            const tick = String.fromCharCode(96);
            const codeBlock = tick + tick + tick + language + '\\n' + (selectedText || '// 在这里输入代码\\n') + '\\n' + tick + tick + tick + '\\n\\n';
            
            textarea.value = textarea.value.substring(0, start) + codeBlock + textarea.value.substring(end);
            
            const newCursorPos = start + language.length + 4;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            textarea.focus();
        }

        function insertImage() {
            const textarea = document.getElementById('editor-textarea');
            if(!textarea) return;

            const imageUrl = prompt('请输入图片 URL 或路径\n(例如: /img/photo.jpg 或 https://example.com/image.png):', '');
            if(!imageUrl) return;

            const altText = prompt('请输入图片描述 (可选):', '图片');
            const width = prompt('图片宽度 (如: 500px, 80%, 留空为原始大小):', '');
            const align = prompt('对齐方式\n输入: left (左对齐), center (居中), right (右对齐)\n留空为默认', 'center');
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            
            let imageHtml = '<div style="text-align: ' + (align || 'center') + ';">\n';
            imageHtml += '  <img src="' + imageUrl + '" alt="' + (altText || '图片') + '"';
            if(width) {
                imageHtml += ' style="width: ' + width + '; height: auto;"';
            }
            imageHtml += '>\n';
            imageHtml += '</div>\n\n';
            
            textarea.value = textarea.value.substring(0, start) + imageHtml + textarea.value.substring(end);
            
            const newCursorPos = start + imageHtml.length;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            textarea.focus();
        }

        async function runCommand(cmd) {
            // 对于预览命令，先自动保存当前编辑内容
            if(cmd === 'preview' && currentDocPath) {
                console.log('Preview: Auto-saving current document...');
                const saveOk = await saveDocument();
                if(!saveOk) {
                    alert('⚠️  预览前保存失败，请检查');
                    return;
                }
                // 等待保存完成
                await new Promise(resolve => setTimeout(resolve, 1500));
            }
            
            try {
                const res = await authFetch('/api/command?name=' + cmd);
                const data = await res.json();
                
                // 对于预览命令，直接打开本地浏览器
                if(cmd === 'preview') {
                    alert(data.message || '✅ 预览已启动！\n\n包括所有草稿文章和最新修改\n浏览器即将打开...');
                    // 给浏览器打开的时间
                    setTimeout(() => {
                        window.open('http://localhost:1313/WangScape/', '_blank');
                    }, 800);
                } else if(data.data && data.data.url) {
                    window.open(data.data.url, '_blank');
                } else {
                    alert('系统: ' + (data.message || data.data?.message || '命令已执行'));
                }
            } catch(e) {
                alert('❌ 命令执行失败: ' + e);
            }
        }

        function switchCommentView() {
            if (!currentDocPath) {
                alert('⚠️ 请先选择一篇文章');
                return;
            }
            const metaPanel = document.getElementById('meta-panel');
            const commentsPanel = document.getElementById('comments-panel');
            
            if (commentsPanel.classList.contains('hide')) {
                commentsPanel.classList.remove('hide');
                commentsPanel.classList.add('show');
                metaPanel.style.display = 'none';
                loadComments(currentDocPath);
            } else {
                commentsPanel.classList.remove('show');
                commentsPanel.classList.add('hide');
                metaPanel.style.display = 'block';
            }
        }

        async function loadComments(postPath) {
            try {
                const res = await authFetch('/api/all_comments?path=' + encodeURIComponent(postPath));
                const data = await res.json();
                
                let html = '';
                if (data.data && data.data.length > 0) {
                    data.data.forEach(comment => {
                        const statusBadge = comment.approved ? 
                            '<span style="color:#4CAF50; font-weight:bold;">已批准</span>' : 
                            '<span style="color:#FF9800; font-weight:bold;">待审核</span>';
                        
                        const bg = comment.approved ? '#f9f9f9' : '#fffbf0';
                        const approveBtn = !comment.approved ? 
                            '<button onclick="approveComment(\'' + postPath + '\', \'' + comment.id + '\')" style="padding: 5px 10px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">批准</button>' : '';
                        
                        const ipInfo = comment.ip_address ? '<div style="font-size: 11px; color: #999; margin-top: 5px;"><strong>IP:</strong> ' + escapeHtml(comment.ip_address) + '</div>' : '';
                        const uaInfo = comment.user_agent ? '<div style="font-size: 11px; color: #999; margin-top: 2px; word-break: break-all;"><strong>UA:</strong> ' + escapeHtml(comment.user_agent) + '</div>' : '';
                        
                        html += '<div style="border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 6px; background: ' + bg + ';">' +
                            '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">' +
                            '<div>' +
                            '<strong>' + escapeHtml(comment.author) + '</strong>' +
                            '<span style="font-size: 12px; color: #999;"> · ' + comment.timestamp + '</span>' +
                            '</div>' +
                            statusBadge +
                            '</div>' +
                            '<p style="margin: 10px 0; color: #333; word-break: break-word;">' + escapeHtml(comment.content) + '</p>' +
                            ipInfo + uaInfo +
                            '<div style="display: flex; gap: 10px; margin-top: 10px;">' +
                            approveBtn +
                            '<button onclick="deleteCommentConfirm(\'' + postPath + '\', \'' + comment.id + '\')" style="padding: 5px 10px; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">删除</button>' +
                            '</div>' +
                            '</div>';
                    });
                } else {
                    html = '<div style="text-align: center; color: #999; padding: 40px;">暂无评论</div>';
                }
                
                document.getElementById('comments-list').innerHTML = html;
            } catch (e) {
                document.getElementById('comments-list').innerHTML = '<div style="color: red;">加载失败: ' + e + '</div>';
            }
        }

        async function approveComment(postPath, commentId) {
            try {
                const res = await authFetch('/api/approve_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ post_path: postPath, comment_id: commentId })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已批准');
                    loadComments(postPath);
                } else {
                    alert('❌ 批准失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        function deleteCommentConfirm(postPath, commentId) {
            if (confirm('确定要删除这条评论吗？此操作不可恢复。')) {
                deleteCommentAction(postPath, commentId);
            }
        }

        async function deleteCommentAction(postPath, commentId) {
            try {
                const res = await authFetch('/api/delete_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ post_path: postPath, comment_id: commentId })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已删除');
                    loadComments(postPath);
                } else {
                    alert('❌ 删除失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        async function loadPendingComments() {
            const listEl = document.getElementById('pending-comments-list');
            const countEl = document.getElementById('pending-total-count');
            const selectAll = document.getElementById('pending-select-all');
            
            listEl.innerHTML = '<div style="text-align:center; padding:40px; color:#999;">加载中...</div>';
            if (selectAll) selectAll.checked = false;
            
            try {
                const res = await authFetch('/api/pending_comments');
                const data = await res.json();
                
                if (data.success && data.data) {
                    const comments = data.data;
                    console.log('[DEBUG] 加载了', comments.length, '条待审核评论');
                    console.log('[DEBUG] 第一条评论数据:', comments[0]);
                    
                    if (comments.length === 0) {
                        listEl.innerHTML = '<div style="text-align:center; padding:60px; color:#999; font-size:16px;">🎉 没有待审核的评论</div>';
                        countEl.textContent = '0 条待审核';
                        return;
                    }
                    
                    countEl.textContent = comments.length + ' 条待审核';
                    const headerCountEl = document.getElementById('pending-total-count-header');
                    if (headerCountEl) {
                        headerCountEl.textContent = comments.length + ' 条待审核';
                    }
                    
                    let html = '';
                    comments.forEach((item, index) => {
                        const c = item;
                        const commentNum = comments.length - index;
                        const truncatedContent = c.content ? (c.content.length > 150 ? c.content.substring(0, 150) + '...' : c.content) : '无内容';
                        
                        let formattedTime = '刚刚';
                        if (c.timestamp) {
                            try {
                                const date = new Date(c.timestamp);
                                if (!isNaN(date.getTime())) {
                                    formattedTime = date.toLocaleString('zh-CN', { 
                                        year: 'numeric',
                                        month: '2-digit',
                                        day: '2-digit',
                                        hour: '2-digit',
                                        minute: '2-digit'
                                    });
                                }
                            } catch(e) {
                                formattedTime = c.timestamp.substring(0, 19);
                            }
                        }
                        
                        html += '<div class="pending-comment-card">' +
                            '<div class="comment-header">' +
                            '<div class="comment-number">#' + commentNum + '</div>' +
                            '<input type="checkbox" class="pending-select" onchange="updateSelectedCount()" data-post="' + c.post_path.replace(/\\/g, '\\\\') + '" data-id="' + c.id + '" data-issue-number="' + (c.issue_number || '') + '" />' +
                            '</div>' +
                            '<div class="comment-post-title">' +
                            '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1V9h-8c-.356 0-.694.074-1 .208V2.5a1 1 0 011-1h8zM5 12.25v3.25a.25.25 0 00.4.2l1.45-1.087a.25.25 0 01.3 0L8.6 15.7a.25.25 0 00.4-.2v-3.25a.25.25 0 00-.25-.25h-3.5a.25.25 0 00-.25.25z"></path></svg>' +
                            escapeHtml(c.post_title || '未知文章') +
                            '</div>' +
                            '<div class="comment-user-info">' +
                            '<div class="user-avatar">' + (c.author ? c.author.substring(0, 1).toUpperCase() : 'U') + '</div>' +
                            '<div class="user-details">' +
                            '<div class="comment-author">' + escapeHtml(c.author || '匿名') + '</div>' +
                            '<div class="comment-meta">' +
                            '<span class="meta-item"><svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M1.75 2A1.75 1.75 0 003.5 3.75v8.5A1.75 1.75 0 001.75 14h-1.5A.25.25 0 010 13.75v-12A.25.25 0 01.25 1.5h1.5zM11 2a1 1 0 00-1 1v10a1 1 0 001 1h3a1 1 0 001-1V3a1 1 0 00-1-1h-3z"></path></svg> ' + escapeHtml(c.email || '未提供') + '</span>' +
                            '<span class="meta-item"><svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M1.5 8a6.5 6.5 0 1113 0 6.5 6.5 0 01-13 0zM8 0a8 8 0 100 16A8 8 0 008 0zm.5 4.75a.75.75 0 00-1.5 0v3.5a.75.75 0 00.471.696l2.5 1a.75.75 0 00.557-1.392L8.5 7.742V4.75z"></path></svg> ' + formattedTime + '</span>' +
                            '</div>' +
                            '</div>' +
                            '</div>' +
                            '<div class="comment-content-preview">' + escapeHtml(truncatedContent) + '</div>' +
                            '<div class="comment-tech-info">' +
                            '<div class="tech-item"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 110 16A8 8 0 018 0zM1.5 8a6.5 6.5 0 1013 0 6.5 6.5 0 00-13 0zm9.78-2.22a.75.75 0 00-1.06-1.06L6.75 8.19 5.28 6.72a.75.75 0 00-1.06 1.06l2 2a.75.75 0 001.06 0l3.5-3.5z"></path></svg> <strong>IP:</strong> ' + escapeHtml(c.ip_address || '未记录') + '</div>' +
                            '<div class="tech-item tech-ua"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1V9h-8c-.356 0-.694.074-1 .208V2.5a1 1 0 011-1h8z"></path></svg> <strong>UA:</strong> ' + (c.user_agent ? escapeHtml(c.user_agent.length > 80 ? c.user_agent.substring(0, 80) + '...' : c.user_agent) : '未记录') + '</div>' +
                            '</div>' +
                            '<div class="comment-actions">' +
                            '<button class="btn-approve" data-action="approve" data-post-path="' + c.post_path + '" data-comment-id="' + c.id + '" data-issue-number="' + (c.issue_number || '') + '">✅ 批准</button>' +
                            '<button class="btn-edit" data-action="edit" data-post-path="' + c.post_path + '" data-comment-id="' + c.id + '" data-issue-number="' + (c.issue_number || '') + '" data-author="' + (c.author || '') + '" data-email="' + (c.email || '') + '" data-content="' + (c.content || '').replace(/"/g, '&quot;') + '">✏️ 编辑</button>' +
                            '<button class="btn-delete" data-action="delete" data-post-path="' + c.post_path + '" data-comment-id="' + c.id + '" data-issue-number="' + (c.issue_number || '') + '">🗑 删除</button>' +
                            '</div>' +
                            '</div>';
                    });
                    
                    listEl.innerHTML = html;
                    
                    // 添加按钮点击事件监听
                    listEl.querySelectorAll('.comment-actions button').forEach(btn => {
                        btn.addEventListener('click', function(e) {
                            e.preventDefault();
                            const action = this.getAttribute('data-action');
                            const postPath = this.getAttribute('data-post-path');
                            const commentId = this.getAttribute('data-comment-id');
                            const issueNumberStr = this.getAttribute('data-issue-number');
                            const issueNumber = issueNumberStr ? parseInt(issueNumberStr) : null;
                            
                            console.log('[DEBUG] 按钮点击:', { action, postPath, commentId, issueNumber, issueNumberStr });
                            
                            if (action === 'approve') {
                                approvePendingComment(postPath, commentId, issueNumber);
                            } else if (action === 'edit') {
                                const author = this.getAttribute('data-author');
                                const email = this.getAttribute('data-email');
                                const content = this.getAttribute('data-content');
                                editPendingComment(postPath, commentId, issueNumber, author, email, content);
                            } else if (action === 'delete') {
                                deletePendingComment(postPath, commentId, issueNumber);
                            }
                        });
                    });
                } else {
                    listEl.innerHTML = '<div style="text-align:center; padding:40px; color:red;">加载失败</div>';
                }
            } catch (e) {
                listEl.innerHTML = '<div style="text-align:center; padding:40px; color:red;">网络错误: ' + e + '</div>';
            }
        }

        function getSelectedPendingItems() {
            const checks = document.querySelectorAll('.pending-select:checked');
            const items = [];
            checks.forEach(ch => {
                const item = {
                    post_path: ch.getAttribute('data-post'),
                    comment_id: ch.getAttribute('data-id')
                };
                // 添加issue_number如果存在
                const issueNumber = ch.getAttribute('data-issue-number');
                if (issueNumber) {
                    item.issue_number = parseInt(issueNumber);
                }
                items.push(item);
            });
            return items;
        }

        function toggleSelectAllPending() {
            const selectAll = document.getElementById('pending-select-all');
            const checks = document.querySelectorAll('.pending-select');
            checks.forEach(ch => ch.checked = selectAll.checked);
            updateSelectedCount();
        }
        
        function updateSelectedCount() {
            const checks = document.querySelectorAll('.pending-select:checked');
            const countEl = document.getElementById('selected-count');
            if (countEl) {
                if (checks.length === 0) {
                    countEl.textContent = '未选择';
                    countEl.style.color = '#6b7280';
                } else {
                    countEl.textContent = '已选择 ' + checks.length + ' 条';
                    countEl.style.color = '#059669';
                    countEl.style.fontWeight = '600';
                }
            }
        }

        async function bulkApprovePending() {
            const items = getSelectedPendingItems();
            if (items.length === 0) {
                alert('请选择要批准的评论');
                return;
            }
            try {
                const res = await authFetch('/api/bulk_comments', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'approve', items: items })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 批量批准完成');
                    loadPendingComments();
                } else {
                    alert('❌ 批量批准失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        async function bulkDeletePending() {
            const items = getSelectedPendingItems();
            if (items.length === 0) {
                alert('请选择要删除的评论');
                return;
            }
            if (!confirm('确定要批量删除所选评论吗？此操作不可恢复。')) return;
            try {
                const res = await authFetch('/api/bulk_comments', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'delete', items: items })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 批量删除完成');
                    loadPendingComments();
                } else {
                    alert('❌ 批量删除失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        async function exportCommentsCsv() {
            try {
                const res = await authFetch('/api/export_comments');
                if (!res.ok) {
                    alert('❌ 导出失败');
                    return;
                }
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'comments.csv';
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
            } catch (e) {
                alert('❌ 导出失败: ' + e);
            }
        }

        async function loadCommentSettings() {
            try {
                const res = await authFetch('/api/comment_settings');
                const data = await res.json();
                if (data.success && data.data) {
                    const s = data.data;
                    document.getElementById('smtp-enabled').checked = !!s.smtp_enabled;
                    document.getElementById('smtp-host').value = s.smtp_host || '';
                    document.getElementById('smtp-port').value = s.smtp_port || 587;
                    document.getElementById('smtp-user').value = s.smtp_user || '';
                    document.getElementById('smtp-pass').value = s.smtp_pass || '';
                    document.getElementById('smtp-from').value = s.smtp_from || '';
                    document.getElementById('smtp-to').value = (s.smtp_to || []).join(',');
                    document.getElementById('notify-pending').checked = !!s.notify_on_pending;
                    document.getElementById('blacklist-ips').value = (s.blacklist_ips || []).join('\n');
                    document.getElementById('blacklist-words').value = (s.blacklist_keywords || []).join('\n');
                }
            } catch (e) {
                console.error('加载评论设置失败:', e);
            }
        }

        async function testMailConnection() {
            const smtpHost = document.getElementById('smtp-host').value.trim();
            const smtpPort = parseInt(document.getElementById('smtp-port').value || '587', 10);
            const smtpUser = document.getElementById('smtp-user').value.trim();
            const smtpPass = document.getElementById('smtp-pass').value.trim();
            const smtpFrom = document.getElementById('smtp-from').value.trim();
            const smtpTo = document.getElementById('smtp-to').value.trim();

            if (!smtpHost || !smtpPort || !smtpUser || !smtpPass || !smtpTo) {
                alert('❌ 请填写所有SMTP配置字段');
                return;
            }

            try {
                const res = await authFetch('/api/test_mail', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        smtp_host: smtpHost,
                        smtp_port: smtpPort,
                        smtp_user: smtpUser,
                        smtp_pass: smtpPass,
                        smtp_from: smtpFrom || smtpUser,
                        smtp_to: smtpTo
                    })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ ' + data.message);
                } else {
                    alert('❌ 测试失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        async function saveCommentSettings() {
            const payload = {
                smtp_enabled: document.getElementById('smtp-enabled').checked,
                smtp_host: document.getElementById('smtp-host').value.trim(),
                smtp_port: parseInt(document.getElementById('smtp-port').value || '587', 10),
                smtp_user: document.getElementById('smtp-user').value.trim(),
                smtp_pass: document.getElementById('smtp-pass').value.trim(),
                smtp_from: document.getElementById('smtp-from').value.trim(),
                smtp_to: document.getElementById('smtp-to').value.split(',').map(s => s.trim()).filter(Boolean),
                notify_on_pending: document.getElementById('notify-pending').checked,
                blacklist_ips: document.getElementById('blacklist-ips').value.split('\n').map(s => s.trim()).filter(Boolean),
                blacklist_keywords: document.getElementById('blacklist-words').value.split('\n').map(s => s.trim()).filter(Boolean)
            };

            try {
                const res = await authFetch('/api/save_comment_settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 设置已保存');
                } else {
                    alert('❌ 保存失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }
        
        async function approvePendingComment(postPath, commentId, issueNumber) {
            console.log('[DEBUG] approvePendingComment called:', { postPath, commentId, issueNumber });
            try {
                const payload = {
                    post_path: postPath,
                    comment_id: commentId
                };
                
                // 如果有issue_number，添加到请求中
                if (issueNumber) {
                    payload.issue_number = parseInt(issueNumber);
                }
                
                const res = await authFetch('/api/approve_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已批准');
                    addOperationHistory('comment', 'approve', postPath, '评论ID: ' + commentId);
                    loadPendingComments();
                } else {
                    alert('❌ 批准失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }
        
        function editPendingComment(postPath, commentId, issueNumber, currentAuthor, currentEmail, currentContent) {
            const modal = document.createElement('div');
            modal.className = 'modal-overlay';
            modal.innerHTML = 
                '<div class="modal-card" style="max-width: 600px;">' +
                    '<h2 style="margin-top: 0;">✏️ 编辑评论</h2>' +
                    '<div style="margin-bottom: 15px;">' +
                        '<label style="display: block; margin-bottom: 5px; font-weight: bold;">作者名称：</label>' +
                        '<input type="text" id="edit-author" value="' + escapeHtml(currentAuthor) + '" style="width: 100%; padding: 8px; border: 1px solid #e2e8f0; border-radius: 4px;" />' +
                    '</div>' +
                    '<div style="margin-bottom: 15px;">' +
                        '<label style="display: block; margin-bottom: 5px; font-weight: bold;">邮箱：</label>' +
                        '<input type="email" id="edit-email" value="' + escapeHtml(currentEmail) + '" style="width: 100%; padding: 8px; border: 1px solid #e2e8f0; border-radius: 4px;" />' +
                    '</div>' +
                    '<div style="margin-bottom: 15px;">' +
                        '<label style="display: block; margin-bottom: 5px; font-weight: bold;">评论内容：</label>' +
                        '<textarea id="edit-content" rows="6" style="width: 100%; padding: 8px; border: 1px solid #e2e8f0; border-radius: 4px; resize: vertical;">' + escapeHtml(currentContent) + '</textarea>' +
                    '</div>' +
                    '<div style="display: flex; gap: 10px; justify-content: flex-end;">' +
                        '<button onclick="this.closest(\'.modal-overlay\').remove()" style="padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer;">取消</button>' +
                        '<button onclick="saveEditedComment(\'' + postPath.replace(/\\/g, '\\\\') + '\', \'' + commentId + '\', ' + (issueNumber || 'null') + ')" style="padding: 8px 16px; background: #0ea5e9; color: white; border: none; border-radius: 4px; cursor: pointer;">💾 保存</button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(modal);
            modal.style.display = 'flex';
        }
        
        async function saveEditedComment(postPath, commentId, issueNumber) {
            console.log('[DEBUG] saveEditedComment called:', { postPath, commentId, issueNumber });
            const author = document.getElementById('edit-author').value.trim();
            const email = document.getElementById('edit-email').value.trim();
            const content = document.getElementById('edit-content').value.trim();
            
            if (!author || !email || !content) {
                alert('请填写所有字段');
                return;
            }
            
            try {
                const payload = {
                    post_path: postPath,
                    comment_id: commentId,
                    author: author,
                    email: email,
                    content: content
                };
                
                if (issueNumber) {
                    payload.issue_number = parseInt(issueNumber);
                }
                
                const res = await authFetch('/api/update_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已更新');
                    document.querySelector('.modal-overlay').remove();
                    addOperationHistory('comment', 'edit', postPath, '评论ID: ' + commentId);
                    loadPendingComments();
                } else {
                    alert('❌ 更新失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }
        
        function deletePendingComment(postPath, commentId, issueNumber) {
            if (confirm('确定要删除这条评论吗？此操作不可恢复。')) {
                deletePendingCommentAction(postPath, commentId, issueNumber);
            }
        }
        
        async function deletePendingCommentAction(postPath, commentId, issueNumber) {
            console.log('[DEBUG] deletePendingCommentAction called:', { postPath, commentId, issueNumber });
            try {
                const payload = { 
                    post_path: postPath, 
                    comment_id: commentId
                };
                
                // 如果有issue_number，添加到请求中
                if (issueNumber) {
                    payload.issue_number = parseInt(issueNumber);
                }
                
                const res = await authFetch('/api/delete_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                console.log('[DEBUG] deletePendingCommentAction response status:', res.status);
                const data = await res.json();
                console.log('[DEBUG] deletePendingCommentAction response data:', data);
                if (data.success) {
                    alert('✅ 评论已删除');
                    addOperationHistory('comment', 'delete', postPath, '评论ID: ' + commentId);

                    loadPendingComments();
                } else {
                    alert('❌ 删除失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }

        function updateWordCount() {
            const textarea = document.getElementById('editor-textarea');
            if (!textarea) return;
            
            const content = textarea.value;
            const bodyContent = content.replace(/^---[\s\S]*?---\n/, '');
            const chineseChars = (bodyContent.match(/[\u4e00-\u9fa5]/g) || []).length;
            const englishWords = (bodyContent.match(/[a-zA-Z]+/g) || []).length;
            const totalWords = chineseChars + englishWords;
            
            const wordCountEl = document.getElementById('word-count');
            if (wordCountEl) {
                wordCountEl.textContent = '字数: ' + totalWords.toLocaleString();
            }
        }
        
        function toggleMetadataPanel() {
            const metaPanel = document.getElementById('meta-panel');
            const commentsPanel = document.getElementById('comments-panel');
            
            if (metaPanel.style.display === 'none') {
                metaPanel.style.display = 'block';
                commentsPanel.classList.add('hide');
                commentsPanel.classList.remove('show');
            } else {
                metaPanel.style.display = 'none';
            }
        }
        
        function insertTable() {
            const textarea = document.getElementById('editor-textarea');
            if (!textarea) return;
            
            const rows = prompt('请输入表格行数：', '3');
            const cols = prompt('请输入表格列数：', '3');
            
            if (!rows || !cols || isNaN(rows) || isNaN(cols)) return;
            
            const numRows = parseInt(rows);
            const numCols = parseInt(cols);
            
            let table = '\n| ';
            for (let i = 0; i < numCols; i++) {
                table += '列' + (i + 1) + ' | ';
            }
            table += '\n| ';
            for (let i = 0; i < numCols; i++) {
                table += '--- | ';
            }
            
            for (let i = 0; i < numRows; i++) {
                table += '\n| ';
                for (let j = 0; j < numCols; j++) {
                    table += '内容 | ';
                }
            }
            table += '\n\n';
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            textarea.value = textarea.value.substring(0, start) + table + textarea.value.substring(end);
            textarea.focus();
            updateWordCount();
        }
        
        function insertMarkdown(before, after) {
            const textarea = document.getElementById('editor-textarea');
            if (!textarea) return;
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const selectedText = textarea.value.substring(start, end);
            
            const newText = before + (selectedText || '文本') + after;
            textarea.value = textarea.value.substring(0, start) + newText + textarea.value.substring(end);
            
            if (selectedText) {
                textarea.setSelectionRange(start, start + newText.length);
            } else {
                textarea.setSelectionRange(start + before.length, start + before.length + 2);
            }
            textarea.focus();
        }

        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }

        fetchPosts();
        fetchCommentStats();
        updateAuthStatus();
        
        // 快捷键支持
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                saveDocument();
            }
            if (e.ctrlKey && e.key === 'b') {
                e.preventDefault();
                insertMarkdown('**', '**');
            }
            if (e.ctrlKey && e.key === 'i') {
                e.preventDefault();
                insertMarkdown('*', '*');
            }
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                const backtick = String.fromCharCode(96);
                insertMarkdown(backtick, backtick);
            }
        });

        // ===== 操作历史管理 =====
        let operationHistory = [];

        function loadOperationHistory() {
            const stored = localStorage.getItem('operationHistory');
            operationHistory = stored ? JSON.parse(stored) : [];
            
            const filterComments = document.getElementById('filter-comments')?.checked ?? true;
            const filterPosts = document.getElementById('filter-posts')?.checked ?? true;
            const dateFrom = document.getElementById('history-date-from')?.value;
            const dateTo = document.getElementById('history-date-to')?.value;
            
            let filtered = operationHistory.filter(op => {
                let typeMatch = (op.type === 'comment' && filterComments) || (op.type === 'post' && filterPosts);
                let dateMatch = true;
                if (dateFrom) {
                    dateMatch = dateMatch && new Date(op.timestamp) >= new Date(dateFrom);
                }
                if (dateTo) {
                    const nextDay = new Date(dateTo);
                    nextDay.setDate(nextDay.getDate() + 1);
                    dateMatch = dateMatch && new Date(op.timestamp) < nextDay;
                }
                return typeMatch && dateMatch;
            });
            
            // 按时间倒序排列
            filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            // 更新统计
            document.getElementById('total-ops').textContent = filtered.length;
            document.getElementById('total-comment-ops').textContent = filtered.filter(op => op.type === 'comment').length;
            document.getElementById('total-post-ops').textContent = filtered.filter(op => op.type === 'post').length;
            
            // 渲染列表
            const historyList = document.getElementById('history-list');
            historyList.innerHTML = filtered.length === 0 
                ? '<div style="text-align:center; padding:40px 20px; color:#999; font-size:14px;">暂无操作记录</div>'
                : filtered.map(op => renderHistoryItem(op)).join('');
        }

        function renderHistoryItem(op) {
            const date = new Date(op.timestamp);
            const timeStr = date.toLocaleString('zh-CN', {year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'});
            const icon = getOperationIcon(op.action);
            const color = getOperationColor(op.action);
            const actionText = getOperationText(op.action);
            const typeText = op.type === 'comment' ? '💬评论' : '📝文章';
            const opTypeText = op.type === 'comment' ? '评论操作' : '文章操作';
            const titleDisplay = op.title ? ' - ' + escapeHtml(op.title.substring(0, 50)) : '';
            const detailsHtml = op.details ? '<div style="font-size:12px; color:#6b7280; padding:8px; background:#f9fafb; border-radius:4px; margin-top:8px;">' + escapeHtml(op.details) + '</div>' : '';
            
            let html = '<div style="background:white; padding:15px; border-radius:8px; border-left:4px solid ' + color + '; box-shadow:0 1px 3px rgba(0,0,0,0.1);">' +
                '<div style="display:flex; justify-content:space-between; align-items:start; margin-bottom:8px;">' +
                '<div style="display:flex; align-items:center; gap:10px; flex:1;">' +
                '<span style="font-size:24px;">' + icon + '</span>' +
                '<div style="flex:1;">' +
                '<div style="font-weight:600; color:#1f2937;">' +
                '[' + typeText + '] ' + actionText + titleDisplay +
                '</div>' +
                '<div style="font-size:12px; color:#6b7280; margin-top:4px;">' + timeStr + '</div>' +
                '</div>' +
                '</div>' +
                '<div style="text-align:right;">' +
                '<span style="display:inline-block; padding:4px 8px; background:' + color + '20; color:' + color + '; border-radius:4px; font-size:12px; font-weight:600;">' +
                opTypeText +
                '</span>' +
                '</div>' +
                '</div>' +
                detailsHtml +
                '</div>';
            return html;
        }

        function getOperationIcon(action) {
            const icons = {
                'approve': '✅',
                'reject': '❌',
                'delete': '🗑️',
                'publish': '📤',
                'create': '✨',
                'edit': '✏️',
                'unpublish': '🔒'
            };
            return icons[action] || '📌';
        }

        function getOperationColor(action) {
            const colors = {
                'approve': '#22c55e',
                'reject': '#ef4444',
                'delete': '#f97316',
                'publish': '#3b82f6',
                'create': '#8b5cf6',
                'edit': '#f59e0b',
                'unpublish': '#6b7280'
            };
            return colors[action] || '#6b7280';
        }

        function getOperationText(action) {
            const texts = {
                'approve': '已批准',
                'reject': '已拒绝',
                'delete': '已删除',
                'publish': '已发布',
                'create': '新建文章',
                'edit': '编辑文章',
                'unpublish': '已下架'
            };
            return texts[action] || action;
        }

        function addOperationHistory(type, action, title = '', details = '') {
            operationHistory.push({
                type: type, // 'comment' 或 'post'
                action: action, // 'approve', 'reject', 'delete', 'publish', 'create', 'edit', 'unpublish'
                title: title,
                details: details,
                timestamp: new Date().toISOString()
            });
            localStorage.setItem('operationHistory', JSON.stringify(operationHistory));
        }

        function exportHistoryCsv() {
            if (operationHistory.length === 0) {
                alert('没有操作记录可导出');
                return;
            }
            
            const headers = ['操作类型', '操作', '标题', '详情', '时间'];
            const rows = operationHistory.map(op => [
                op.type === 'comment' ? '评论' : '文章',
                getOperationText(op.action),
                op.title || '-',
                op.details || '-',
                new Date(op.timestamp).toLocaleString('zh-CN')
            ]);
            
            const csv = [headers, ...rows].map(row => 
                row.map(cell => '"' + String(cell).replace(/"/g, '""') + '"')
                   .join(',')
            ).join('\n');
            
            const blob = new Blob([csv], {type: 'text/csv;charset=utf-8;'});
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            const dateStr = new Date().toISOString().split('T')[0];
            link.download = '操作历史_' + dateStr + '.csv';
            link.click();
        }

        // 初始化历史记录
        loadOperationHistory();
    </script>
</body>
</html>`
