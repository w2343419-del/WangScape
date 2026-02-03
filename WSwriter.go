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
	ID        string   `json:"id"`
	Author    string   `json:"author"`
	Email     string   `json:"email"`
	Content   string   `json:"content"`
	Timestamp string   `json:"timestamp"`
	Approved  bool     `json:"approved"`
	PostPath  string   `json:"post_path"`
	IPAddress string   `json:"ip_address"`
	UserAgent string   `json:"user_agent"`
    ParentID  string   `json:"parent_id,omitempty"`
    Images    []string `json:"images,omitempty"`
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

// PostLikes represents likes data for a post
type PostLikes struct {
	PostPath string   `json:"post_path"`
	Likes    int      `json:"likes"`
	LikedIPs []string `json:"liked_ips"`
}

// LikesFile represents all posts likes data
type LikesFile struct {
	Likes []PostLikes `json:"likes"`
}

func getCommentSettingsPath() string {
    return filepath.Join(hugoPath, "config", "comment_settings.json")
}

func getLikesPath() string {
    return filepath.Join(hugoPath, "config", "post_likes.json")
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

func loadPostLikes() LikesFile {
    path := getLikesPath()
    likesFile := LikesFile{Likes: []PostLikes{}}
    
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return likesFile
    }
    
    content, err := os.ReadFile(path)
    if err != nil {
        return likesFile
    }
    
    if err := json.Unmarshal(content, &likesFile); err != nil {
        return likesFile
    }
    
    return likesFile
}

func savePostLikes(likesFile LikesFile) error {
    path := getLikesPath()
    data, err := json.MarshalIndent(likesFile, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}

func getPostLikes(postPath string) PostLikes {
    likesFile := loadPostLikes()
    for _, pl := range likesFile.Likes {
        if pl.PostPath == postPath {
            return pl
        }
    }
    return PostLikes{PostPath: postPath, Likes: 0, LikedIPs: []string{}}
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
    if !settings.SMTPEnabled || !settings.NotifyOnPending {
        return nil
    }

    from := settings.SMTPFrom
    if from == "" {
        from = settings.SMTPUser
    }
    if from == "" || len(settings.SMTPTo) == 0 || settings.SMTPHost == "" || settings.SMTPPort == 0 {
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
        client, err := smtp.Dial(addr)
        if err != nil {
            return err
        }
        defer client.Close()
        
        // 升级到TLS
        if err := client.StartTLS(&tls.Config{ServerName: settings.SMTPHost}); err != nil {
            return err
        }
        
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
		log.Printf("[WARN] Failed to generate JWT secret: %v", err)
		jwtSecret = []byte("default-insecure-key")
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
        return false
    }
	
    if passwordHash != "" {
        sum := sha256.Sum256([]byte(password))
        calc := hex.EncodeToString(sum[:])
        return subtle.ConstantTimeCompare([]byte(calc), []byte(passwordHash)) == 1
    }
	
    return subtle.ConstantTimeCompare([]byte(password), []byte(passwordEnv)) == 1
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
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }
    data.Username = strings.TrimSpace(data.Username)

    if !verifyAdminCredentials(data.Username, data.Password) {
        writeAuditLog("login_failed", r, map[string]interface{}{"username": data.Username})
        respondJSON(w, http.StatusUnauthorized, APIResponse{Success: false, Message: "用户名或密码错误"})
        return
    }

    // 生成访问令牌 (短期)
    accessToken, err := createJWT(data.Username, "access")
    if err != nil {
        writeAuditLog("login_error", r, map[string]interface{}{"username": data.Username, "error": err.Error()})
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成令牌失败"})
        return
    }

    // 生成刷新令牌 (长期)
    refreshToken, err := createJWT(data.Username, "refresh")
    if err != nil {
        writeAuditLog("login_error", r, map[string]interface{}{"username": data.Username, "error": err.Error()})
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "生成刷新令牌失败"})
        return
    }

    accessExpiresAt := time.Now().Add(getJWTExpiry()).Format(time.RFC3339)
    refreshExpiresAt := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
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

func handleGetComments(w http.ResponseWriter, r *http.Request) {
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
        postTitle := ""
        fullPath := filepath.Join(hugoPath, data.PostPath)
        if content, err := os.ReadFile(fullPath); err == nil {
            fm := parseFrontmatter(string(content))
            postTitle = fm.Title
        }
        _ = sendCommentNotification(settings, comment, postTitle)
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
		PostPath  string `json:"post_path"`
		CommentID string `json:"comment_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := approveComment(data.PostPath, data.CommentID); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("approve_comment", r, map[string]interface{}{ "post_path": data.PostPath, "comment_id": data.CommentID })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已批准"})
}

func handleDeleteComment(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感操作
	if !requireLocal(w, r) {
		return
	}

	var data struct {
		PostPath  string `json:"post_path"`
		CommentID string `json:"comment_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	if err := deleteComment(data.PostPath, data.CommentID); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}
    writeAuditLog("delete_comment", r, map[string]interface{}{ "post_path": data.PostPath, "comment_id": data.CommentID })
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已删除"})
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

	stats := getAllCommentsStats()
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: stats})
}

func handleGetPendingComments(w http.ResponseWriter, r *http.Request) {
	// 仅允许本地访问敏感数据
	if !requireLocal(w, r) {
		return
	}

	var pendingComments []CommentWithPost

	// 遍历所有文章，收集未审核评论
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
            PostPath  string `json:"post_path"`
            CommentID string `json:"comment_id"`
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

    for _, item := range data.Items {
        if data.Action == "approve" {
            _ = approveComment(item.PostPath, item.CommentID)
        } else {
            _ = deleteComment(item.PostPath, item.CommentID)
        }
    }
    writeAuditLog("bulk_comments", r, map[string]interface{}{"action": data.Action, "count": len(data.Items)})
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "OK"})
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
            if !isAllowedOrigin(origin) {
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

func isAllowedOrigin(origin string) bool {
    allowed := map[string]bool{
        "http://localhost:1313":  true,
        "http://127.0.0.1:1313": true,
        "http://localhost:8080":  true,
        "http://127.0.0.1:8080": true,
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
// handleLikePost handles liking a post
func handleLikePost(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var data struct {
        PostPath string `json:"post_path"`
    }

    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    // Get client IP
    ip := getRealClientIP(r)
    if !allowRequest("like_post:"+ip, 20, time.Minute) {
        respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
        return
    }

    // Load all likes
    likesFile := loadPostLikes()
    
    // Find or create post likes
    found := false
    for i := range likesFile.Likes {
        if likesFile.Likes[i].PostPath == data.PostPath {
            // Check if IP already liked
            for _, likedIP := range likesFile.Likes[i].LikedIPs {
                if likedIP == ip {
                    respondJSON(w, http.StatusOK, APIResponse{
                        Success: false,
                        Message: "Already liked",
                        Data:    map[string]int{"likes": likesFile.Likes[i].Likes},
                    })
                    return
                }
            }
            
            // Add like
            likesFile.Likes[i].Likes++
            likesFile.Likes[i].LikedIPs = append(likesFile.Likes[i].LikedIPs, ip)
            found = true
            
            if err := savePostLikes(likesFile); err != nil {
                respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to save"})
                return
            }
            
            respondJSON(w, http.StatusOK, APIResponse{
                Success: true,
                Message: "Liked",
                Data:    map[string]int{"likes": likesFile.Likes[i].Likes},
            })
            return
        }
    }

    // If not found, create new
    if !found {
        newLikes := PostLikes{
            PostPath: data.PostPath,
            Likes:    1,
            LikedIPs: []string{ip},
        }
        likesFile.Likes = append(likesFile.Likes, newLikes)
        
        if err := savePostLikes(likesFile); err != nil {
            respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to save"})
            return
        }
        
        respondJSON(w, http.StatusOK, APIResponse{
            Success: true,
            Message: "Liked",
            Data:    map[string]int{"likes": 1},
        })
    }
}

// handleUnlikePost handles unliking a post
func handleUnlikePost(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var data struct {
        PostPath string `json:"post_path"`
    }

    if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    // Get client IP
    ip := getRealClientIP(r)
    if !allowRequest("unlike_post:"+ip, 20, time.Minute) {
        respondJSON(w, http.StatusTooManyRequests, APIResponse{Success: false, Message: "请求过于频繁"})
        return
    }

    // Load all likes
    likesFile := loadPostLikes()
    
    // Find post likes
    for i := range likesFile.Likes {
        if likesFile.Likes[i].PostPath == data.PostPath {
            // Check if IP liked before
            ipIndex := -1
            for j, likedIP := range likesFile.Likes[i].LikedIPs {
                if likedIP == ip {
                    ipIndex = j
                    break
                }
            }
            
            if ipIndex == -1 {
                respondJSON(w, http.StatusOK, APIResponse{
                    Success: false,
                    Message: "Not liked yet",
                    Data:    map[string]int{"likes": likesFile.Likes[i].Likes},
                })
                return
            }
            
            // Remove like
            if likesFile.Likes[i].Likes > 0 {
                likesFile.Likes[i].Likes--
            }
            likesFile.Likes[i].LikedIPs = append(likesFile.Likes[i].LikedIPs[:ipIndex], likesFile.Likes[i].LikedIPs[ipIndex+1:]...)
            
            if err := savePostLikes(likesFile); err != nil {
                respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: "Failed to save"})
                return
            }
            
            respondJSON(w, http.StatusOK, APIResponse{
                Success: true,
                Message: "Unliked",
                Data:    map[string]int{"likes": likesFile.Likes[i].Likes},
            })
            return
        }
    }

    respondJSON(w, http.StatusOK, APIResponse{
        Success: false,
        Message: "Post not found",
        Data:    map[string]int{"likes": 0},
    })
}

// handleGetLikes returns likes data for all posts or a specific post
func handleGetLikes(w http.ResponseWriter, r *http.Request) {
    postPath := r.URL.Query().Get("path")
    
    if postPath != "" {
        // Get likes for specific post
        likes := getPostLikes(postPath)
        
        // Check if current IP liked
        ip := r.RemoteAddr
        if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
            ip = strings.Split(forwarded, ",")[0]
        }
        
        liked := false
        for _, likedIP := range likes.LikedIPs {
            if likedIP == ip {
                liked = true
                break
            }
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "likes": likes.Likes,
            "liked": liked,
        })
    } else {
        // Get all likes
        likesFile := loadPostLikes()
        likesMap := make(map[string]int)
        for _, likes := range likesFile.Likes {
            likesMap[likes.PostPath] = likes.Likes
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(likesMap)
    }
}

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

func main() {
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
    rootMux.HandleFunc("/api/all_comments", withCORS(withAuth(handleGetAllComments)))
    rootMux.HandleFunc("/api/comment_stats", withCORS(withAuth(handleCommentStats)))
    rootMux.HandleFunc("/api/pending_comments", withCORS(withAuth(handleGetPendingComments)))
    rootMux.HandleFunc("/api/comment_settings", withCORS(withAuth(handleGetCommentSettings)))
    rootMux.HandleFunc("/api/save_comment_settings", withCORS(withAuth(limitRequestBody(handleSaveCommentSettings, 1<<20))))
    rootMux.HandleFunc("/api/bulk_comments", withCORS(withAuth(limitRequestBody(handleBulkComments, 1<<20))))
    rootMux.HandleFunc("/api/export_comments", withCORS(withAuth(handleExportComments)))
    rootMux.HandleFunc("/api/like_post", withCORS(limitRequestBody(handleLikePost, 512)))
    rootMux.HandleFunc("/api/unlike_post", withCORS(limitRequestBody(handleUnlikePost, 512)))
    rootMux.HandleFunc("/api/get_likes", withCORS(handleGetLikes))

	// 启动审计日志轮转
	go rotateAuditLogPeriodically()

	// 获取端口配置
	httpPort := getEnv("HTTP_PORT", "8080")
	httpsPort := getEnv("HTTPS_PORT", "443")
	tlsCertFile := getEnv("TLS_CERT_FILE", "")
	tlsKeyFile := getEnv("TLS_KEY_FILE", "")

	// Start HTTP server
	fmt.Printf("WangScape Writer Online: http://127.0.0.1:%s\n", httpPort)
	openBrowser(fmt.Sprintf("http://127.0.0.1:%s", httpPort))

	// 启动HTTP监听
	go func() {
		httpAddr := fmt.Sprintf(":%s", httpPort)
		if err := http.ListenAndServe(httpAddr, wrappedMux); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[AUDIT] HTTP Server error: %v\n", err)
		}
	}()

	// 启动HTTPS监听 (如果配置了证书)
	if tlsCertFile != "" && tlsKeyFile != "" {
		if _, err := os.Stat(tlsCertFile); err == nil {
			if _, err := os.Stat(tlsKeyFile); err == nil {
				go func() {
					httpsAddr := fmt.Sprintf(":%s", httpsPort)
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
            --dash-bg: #f7f8fb;
            --dash-sidebar: #0f172a;
            --dash-text: #0f172a;
            --dash-text-dim: #64748b;
            --dash-accent: #4f46e5;
            --dash-border: #e2e8f0;
            --word-bg: #eef2f7;
            --word-blue: #2563eb;
            --word-paper: #ffffff;
            --word-text: #0f172a;
            --word-border: #e2e8f0;
            --font-main: 'Inter', 'Noto Sans SC', sans-serif;
        }

        body {
            margin: 0;
            font-family: var(--font-main);
            overflow: hidden;
            height: 100vh;
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
            width: 300px;
            background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
            border-right: 1px solid rgba(255,255,255,0.08);
            padding: 28px;
            display: flex;
            flex-direction: column;
            gap: 20px;
            box-shadow: 6px 0 18px rgba(15, 23, 42, 0.18);
            --dash-text: #e2e8f0;
            --dash-text-dim: #94a3b8;
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
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.08);
            color: #e2e8f0;
            padding: 12px 14px;
            border-radius: 12px;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 500;
        }

        .dash-btn:hover {
            border-color: rgba(165, 180, 252, 0.4);
            background: rgba(79, 70, 229, 0.18);
            color: #c7d2fe;
        }

        .dash-btn.primary {
            background: linear-gradient(135deg, #a5b4fc 0%, #4f46e5 100%);
            color: #0f172a;
            border: none;
            font-weight: 700;
            box-shadow: 0 8px 18px rgba(79, 70, 229, 0.35);
            transition: all 0.3s ease;
        }

        .dash-btn.primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 24px rgba(79, 70, 229, 0.45);
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
            box-shadow: 0 12px 24px rgba(15, 23, 42, 0.06);
            transition: all 0.3s ease;
        }

        .post-list-card:hover {
            box-shadow: 0 18px 32px rgba(15, 23, 42, 0.1);
            border-color: #cbd5f5;
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

        .like-btn {
            transition: all 0.2s ease;
        }

        .like-btn:hover {
            background: #fff0f3 !important;
            border-color: #ff69b4 !important;
            transform: scale(1.05);
        }

        .like-btn.liked {
            background: #ffe7e7 !important;
            border-color: #e91e63 !important;
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
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }

        .modal-card {
            background: #1a1a1a;
            color: white;
            width: 500px;
            padding: 30px;
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }

        .modal-card input {
            width: 100%;
            padding: 12px;
            background: #000;
            border: 1px solid rgba(255,255,255,0.2);
            color: white;
            border-radius: 8px;
            margin-top: 8px;
            margin-bottom: 20px;
            box-sizing: border-box;
        }

        .modal-card button {
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
        }

        .btn-confirm {
            background: var(--dash-accent);
            color: black;
            border: none;
        }

        .btn-cancel {
            background: transparent;
            color: #ccc;
            border: 1px solid #555;
            margin-right: 10px;
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
            background: var(--dash-sidebar);
            border: 1px solid var(--dash-border);
            border-left: 4px solid #ff9800;
            border-radius: 12px;
            padding: 25px;
            transition: all 0.3s ease;
        }
        
        .pending-comment-card:hover {
            box-shadow: 0 4px 12px rgba(255, 152, 0, 0.2);
            border-left-color: #ff5722;
        }
        
        .comment-post-title {
            font-size: 14px;
            color: #4a90e2;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .comment-meta {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 13px;
            color: var(--dash-text-dim);
        }
        
        .comment-author {
            font-weight: 600;
            color: var(--dash-text);
        }
        
        .comment-content {
            color: var(--dash-text);
            line-height: 1.6;
            margin-bottom: 15px;
            padding: 15px;
            background: rgba(255, 152, 0, 0.05);
            border-radius: 8px;
            word-break: break-word;
        }
        
        .comment-actions {
            display: flex;
            gap: 10px;
        }
        
        .btn-approve {
            padding: 8px 16px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .btn-approve:hover {
            background: #45a049;
            transform: translateY(-1px);
        }
        
        .btn-delete {
            padding: 8px 16px;
            background: #f44336;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .btn-delete:hover {
            background: #da190b;
            transform: translateY(-1px);
        }
        
        .comment-tech-info {
            font-size: 11px;
            color: #999;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }

        .pending-toolbar {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
        }

        .pending-toolbar label {
            font-size: 13px;
            color: var(--dash-text);
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
                    <button class="dash-btn" style="flex:1;" onclick="openLoginModal()">登录</button>
                    <button class="dash-btn" style="flex:1;" onclick="logout()">退出</button>
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
                    <button class="dash-btn" style="flex:1;" onclick="openLoginModal()">登录</button>
                    <button class="dash-btn" style="flex:1;" onclick="logout()">退出</button>
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
            <h1 class="dash-header">待审核评论列表</h1>
            <div class="pending-toolbar">
                <label><input type="checkbox" id="pending-select-all" onchange="toggleSelectAllPending()" /> 全选</label>
                <button class="btn-approve" onclick="bulkApprovePending()">✅ 批量批准</button>
                <button class="btn-delete" onclick="bulkDeletePending()">🗑 批量删除</button>
            </div>
            <div id="pending-comments-list" style="display:flex; flex-direction:column; gap:20px;"></div>
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
        let likesData = {};
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
            const response = await fetch(url, Object.assign({}, options, { headers }));
            if (response.status === 401) {
                openLoginModal('需要登录才能继续操作');
            }
            return response;
        }

        function openLoginModal(message) {
            const modal = document.getElementById('login-modal');
            const hint = document.getElementById('login-hint');
            if (message) {
                hint.textContent = message;
                hint.style.display = 'block';
            } else {
                hint.style.display = 'none';
            }
            modal.style.display = 'flex';
        }

        function closeLoginModal() {
            const modal = document.getElementById('login-modal');
            modal.style.display = 'none';
        }

        async function performLogin() {
            const username = document.getElementById('login-username').value.trim();
            const password = document.getElementById('login-password').value;
            if (!username || !password) {
                openLoginModal('请输入用户名和密码');
                return;
            }
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (data && data.token) {
                setAuthToken(data.token);
                closeLoginModal();
            } else {
                openLoginModal(data.message || '登录失败');
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
        }

        function switchView(view) {
            document.querySelectorAll('.view-section').forEach(e => e.classList.remove('active'));
            document.getElementById(view + '-view').classList.add('active');
            if (view === 'dashboard') {
                fetchPosts();
                fetchCommentStats();
                fetchLikesData();
            } else if (view === 'pending-comments') {
                loadPendingComments();
                loadCommentSettings();
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

        async function fetchLikesData() {
            try {
                const res = await fetch('/api/get_likes');
                likesData = await res.json();
                renderDashboardList();
            } catch(e) {
                console.error('获取点赞数据失败:', e);
            }
        }

        async function toggleLike(postPath, event) {
            event.stopPropagation();
            
            const btn = event.target;
            const isLiked = btn.classList.contains('liked');
            const endpoint = isLiked ? '/api/unlike_post' : '/api/like_post';
            
            try {
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ post_path: postPath })
                });
                const data = await res.json();
                
                if (data.success || data.data) {
                    // 更新本地数据
                    likesData[postPath] = data.data.likes;
                    
                    // 更新按钮状态
                    if (isLiked) {
                        btn.classList.remove('liked');
                        btn.innerHTML = '🤍 ' + (data.data.likes || 0);
                    } else {
                        btn.classList.add('liked');
                        btn.innerHTML = '❤️ ' + (data.data.likes || 0);
                    }
                } else if (data.message === 'Already liked') {
                    // 已经点赞过，更新UI
                    btn.classList.add('liked');
                    btn.innerHTML = '❤️ ' + (data.data.likes || 0);
                }
            } catch(e) {
                console.error('点赞失败:', e);
            }
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
                
                // 显示点赞数
                const likes = likesData[primaryVersion.path] || 0;
                html += '<span style="font-size:9px; padding:2px 4px; background:#ffe7e7; color:#e91e63; border-radius:3px; margin-left:4px;">❤️ ' + likes + '</span>';
                
                html += '</div>' +
                    '<div class="dpi-meta">' + primaryVersion.date + ' · ' + primaryVersion.path + '</div>' +
                    '</div>' +
                    '<div style="display:flex; gap:8px; align-items:center;">' +
                    '<button onclick="toggleLike(\'' + escapedPath + '\', event)" class="like-btn" style="background:#fff; border:1px solid #ffc0cb; color:#e91e63; padding:4px 10px; border-radius:6px; font-size:11px; cursor:pointer; transition:all 0.2s;">🤍 ' + likes + '</button>';
                
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
                    
                    if (comments.length === 0) {
                        listEl.innerHTML = '<div style="text-align:center; padding:60px; color:#999; font-size:16px;">🎉 没有待审核的评论</div>';
                        countEl.textContent = '0 条待审核';
                        return;
                    }
                    
                    countEl.textContent = comments.length + ' 条待审核';
                    
                    let html = '';
                    comments.forEach(item => {
                        const c = item;
                        html += '<div class="pending-comment-card">' +
                            '<div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">' +
                            '<input type="checkbox" class="pending-select" data-post="' + c.post_path.replace(/\\/g, '\\\\') + '" data-id="' + c.id + '" />' +
                            '<div class="comment-post-title">📝 ' + escapeHtml(c.post_title) + '</div>' +
                            '</div>' +
                            '<div class="comment-meta">' +
                            '<span class="comment-author">👤 ' + escapeHtml(c.author) + '</span>' +
                            '<span>📧 ' + escapeHtml(c.email) + '</span>' +
                            '<span>🕐 ' + c.timestamp + '</span>' +
                            '</div>' +
                            '<div class="comment-content">' + escapeHtml(c.content) + '</div>' +
                            '<div class="comment-tech-info">' +
                            '<div>🌐 IP: ' + escapeHtml(c.ip_address || '未记录') + '</div>' +
                            '<div>💻 ' + escapeHtml(c.user_agent || '未记录') + '</div>' +
                            '</div>' +
                            '<div class="comment-actions">' +
                            '<button class="btn-approve" onclick="approvePendingComment(\'' + c.post_path.replace(/\\/g, '\\\\') + '\', \'' + c.id + '\')">✅ 批准</button>' +
                            '<button class="btn-delete" onclick="deletePendingComment(\'' + c.post_path.replace(/\\/g, '\\\\') + '\', \'' + c.id + '\')">🗑 删除</button>' +
                            '</div>' +
                            '</div>';
                    });
                    
                    listEl.innerHTML = html;
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
                items.push({
                    post_path: ch.getAttribute('data-post'),
                    comment_id: ch.getAttribute('data-id')
                });
            });
            return items;
        }

        function toggleSelectAllPending() {
            const selectAll = document.getElementById('pending-select-all');
            const checks = document.querySelectorAll('.pending-select');
            checks.forEach(ch => ch.checked = selectAll.checked);
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
        
        async function approvePendingComment(postPath, commentId) {
            try {
                const res = await authFetch('/api/approve_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ post_path: postPath, comment_id: commentId })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已批准');
                    loadPendingComments();
                } else {
                    alert('❌ 批准失败: ' + data.message);
                }
            } catch (e) {
                alert('❌ 错误: ' + e);
            }
        }
        
        function deletePendingComment(postPath, commentId) {
            if (confirm('确定要删除这条评论吗？此操作不可恢复。')) {
                deletePendingCommentAction(postPath, commentId);
            }
        }
        
        async function deletePendingCommentAction(postPath, commentId) {
            try {
                const res = await authFetch('/api/delete_comment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ post_path: postPath, comment_id: commentId })
                });
                const data = await res.json();
                if (data.success) {
                    alert('✅ 评论已删除');
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
        fetchLikesData();
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
    </script>
</body>
</html>`
