package main

import (
    "bytes"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io/ioutil"
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
    "time"
)

const (
	PORT     = 8080
	htmlPort = 1313
)

var hugoPath string

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
	ID        string `json:"id"`
	Author    string `json:"author"`
	Email     string `json:"email"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
	Approved  bool   `json:"approved"`
	PostPath  string `json:"post_path"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
    ParentID  string `json:"parent_id,omitempty"`
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
        NotifyOnPending: true,
        BlacklistIPs:    []string{},
        BlacklistWords:  []string{},
    }

    if _, err := os.Stat(path); os.IsNotExist(err) {
        return settings
    }

    content, err := ioutil.ReadFile(path)
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
    return ioutil.WriteFile(path, data, 0644)
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
        comment.Author,
        comment.Email,
        comment.Timestamp,
        comment.IPAddress,
        comment.UserAgent,
        comment.Content,
    )

    msg := bytes.NewBuffer(nil)
    msg.WriteString("From: " + from + "\r\n")
    msg.WriteString("To: " + strings.Join(settings.SMTPTo, ",") + "\r\n")
    msg.WriteString("Subject: " + subject + "\r\n")
    msg.WriteString("MIME-Version: 1.0\r\n")
    msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
    msg.WriteString("\r\n")
    msg.WriteString(body)

    addr := settings.SMTPHost + ":" + strconv.Itoa(settings.SMTPPort)
    auth := smtp.PlainAuth("", settings.SMTPUser, settings.SMTPPass, settings.SMTPHost)
    return smtp.SendMail(addr, auth, from, settings.SMTPTo, msg.Bytes())
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
            content, err := ioutil.ReadFile(indexPath)
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

func init() {
	var err error
	hugoPath, err = os.Getwd()
	if err != nil {
		panic(err)
	}
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

// getContent reads file content
func getContent(relPath string) (string, error) {
	fullPath := filepath.Join(hugoPath, relPath)

	// Security check
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}
	absHugo, _ := filepath.Abs(hugoPath)

	if !strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absHugo)) {
		return "", fmt.Errorf("path security violation")
	}

	if !strings.HasSuffix(strings.ToLower(fullPath), ".md") {
		return "", fmt.Errorf("invalid file type")
	}

	if _, err := os.Stat(fullPath); err != nil {
		return "", fmt.Errorf("file not found")
	}

	content, err := ioutil.ReadFile(fullPath)
	return string(content), err
}

// saveContent saves file content
func saveContent(relPath, content string) error {
	fullPath := filepath.Join(hugoPath, relPath)

	// Security check
	if strings.Contains(relPath, "..") || !strings.HasSuffix(strings.ToLower(relPath), ".md") {
		return fmt.Errorf("invalid path")
	}

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return err
	}
	absHugo, _ := filepath.Abs(hugoPath)

	if !strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absHugo)) {
		return fmt.Errorf("path security violation")
	}

	return ioutil.WriteFile(fullPath, []byte(content), 0644)
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
	entries, err := ioutil.ReadDir(parentDir)
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
		content, _ := ioutil.ReadFile(path)
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
	
	content, err := ioutil.ReadFile(fullPath)
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
	
	return ioutil.WriteFile(fullPath, data, 0644)
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
	content, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string

	for _, line := range lines {
		if strings.HasPrefix(line, "title:") {
			newLines = append(newLines, fmt.Sprintf(`title: "%s"`, title))
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

	return ioutil.WriteFile(fullPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// handleCommand executes system commands
func handleCommand(cmd string) (map[string]interface{}, error) {
	switch cmd {
	case "preview":
		// 先杀死可能占用端口的 hugo 进程
		if runtime.GOOS == "windows" {
			exec.Command("taskkill", "/F", "/IM", "hugo.exe").Run()
		} else {
			exec.Command("pkill", "hugo").Run()
		}
		
		time.Sleep(500 * time.Millisecond)
		
		// 先构建一次（包括草稿），确保所有内容都是最新的
		buildCmd := exec.Command("hugo", "--buildDrafts", "--minify")
		buildCmd.Dir = hugoPath
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("Build failed: %s", string(buildOutput))}, err
		}
		
		// 启动预览服务器（后台运行，包括草稿）
		serverCmd := exec.Command("hugo", "server", 
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
		// 1. 先编译网站 - 包含草稿和未来日期的文章
		buildCmd := exec.Command("hugo", "--minify", "--buildDrafts", "--buildFuture")
		buildCmd.Dir = hugoPath
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("❌ Hugo 构建失败:\n%s\n\n请检查文章格式是否正确。", string(buildOutput))}, err
		}
		
		// 2. 检查是否有变更
		statusCmd := exec.Command("git", "status", "--porcelain")
		statusCmd.Dir = hugoPath
		statusOutput, _ := statusCmd.Output()
		if len(strings.TrimSpace(string(statusOutput))) == 0 {
			return map[string]interface{}{"message": "ℹ️  没有任何文件变更，无需提交", "url": ""}, nil
		}
		
		// 3. Git 添加所有更改
		cmd := exec.Command("git", "add", ".")
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

func handleSaveContent(w http.ResponseWriter, r *http.Request) {
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

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Saved"})
}

func handleDeletePost(w http.ResponseWriter, r *http.Request) {
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
	var data struct {
		PostPath string `json:"post_path"`
		Author   string `json:"author"`
		Email    string `json:"email"`
		Content  string `json:"content"`
        ParentID string `json:"parent_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
		return
	}

	// Get IP address
	ipAddress := r.Header.Get("X-Forwarded-For")
	if ipAddress == "" {
		ipAddress = r.Header.Get("X-Real-IP")
	}
	if ipAddress == "" {
		ipAddress = r.RemoteAddr
	}

	// Get User-Agent
	userAgent := r.Header.Get("User-Agent")

    settings := loadCommentSettings()
    if isCommentBlacklisted(settings, ipAddress, data.Author, data.Email, data.Content) {
        respondJSON(w, http.StatusOK, APIResponse{Success: false, Message: "评论被拦截"})
        return
    }

    comment, err := addComment(data.PostPath, data.Author, data.Email, data.Content, ipAddress, userAgent, data.ParentID)
    if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}

    // 发送邮件通知（不阻塞主流程）
    go func() {
        postTitle := ""
        fullPath := filepath.Join(hugoPath, data.PostPath)
        if content, err := ioutil.ReadFile(fullPath); err == nil {
            fm := parseFrontmatter(string(content))
            postTitle = fm.Title
        }
        _ = sendCommentNotification(settings, comment, postTitle)
    }()

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已提交，等待审核"})
}

func handleApproveComment(w http.ResponseWriter, r *http.Request) {
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

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已批准"})
}

func handleDeleteComment(w http.ResponseWriter, r *http.Request) {
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

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "评论已删除"})
}

func handleGetAllComments(w http.ResponseWriter, r *http.Request) {
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
	stats := getAllCommentsStats()
	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: stats})
}

func handleGetPendingComments(w http.ResponseWriter, r *http.Request) {
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
				content, err := ioutil.ReadFile(indexPath)
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
    settings := loadCommentSettings()
    respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: settings})
}

func handleSaveCommentSettings(w http.ResponseWriter, r *http.Request) {
    var settings CommentSettings
    if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
        respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Invalid request"})
        return
    }

    if err := saveCommentSettings(settings); err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
        return
    }

    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "Saved"})
}

func handleBulkComments(w http.ResponseWriter, r *http.Request) {
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

    respondJSON(w, http.StatusOK, APIResponse{Success: true, Message: "OK"})
}

func handleExportComments(w http.ResponseWriter, r *http.Request) {
    comments, err := collectAllComments()
    if err != nil {
        respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
        return
    }

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

	respondJSON(w, http.StatusOK, APIResponse{Success: true, Data: results})
}

func handleCommandAPI(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("name")
	if cmd == "" {
		respondJSON(w, http.StatusBadRequest, APIResponse{Success: false, Message: "Missing command"})
		return
	}

	result, err := handleCommand(cmd)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: err.Error()})
		return
	}

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
	if err := ioutil.WriteFile(enFullPath, []byte(enContent), 0644); err != nil {
		respondJSON(w, http.StatusInternalServerError, APIResponse{Success: false, Message: fmt.Sprintf("Failed to save: %v", err)})
		return
	}

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

func main() {
	// Setup routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/posts", handleGetPosts)
	http.HandleFunc("/api/get_content", handleGetContent)
	http.HandleFunc("/api/save_content", handleSaveContent)
	http.HandleFunc("/api/delete_post", handleDeletePost)
	http.HandleFunc("/api/create_sync", handleCreateSync)
	http.HandleFunc("/api/sync_translate", handleSyncTranslate)
	http.HandleFunc("/api/command", handleCommandAPI)
	http.HandleFunc("/api/comments", handleGetComments)
	http.HandleFunc("/api/add_comment", handleAddComment)
	http.HandleFunc("/api/approve_comment", handleApproveComment)
	http.HandleFunc("/api/delete_comment", handleDeleteComment)
	http.HandleFunc("/api/all_comments", handleGetAllComments)
	http.HandleFunc("/api/comment_stats", handleCommentStats)
	http.HandleFunc("/api/pending_comments", handleGetPendingComments)
    http.HandleFunc("/api/comment_settings", handleGetCommentSettings)
    http.HandleFunc("/api/save_comment_settings", handleSaveCommentSettings)
    http.HandleFunc("/api/bulk_comments", handleBulkComments)
    http.HandleFunc("/api/export_comments", handleExportComments)

	// Start server
	fmt.Printf("WangScape Writer Online: http://127.0.0.1:%d\n", PORT)
	openBrowser(fmt.Sprintf("http://127.0.0.1:%d", PORT))

	if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", PORT), nil); err != nil {
		fmt.Println("Server error:", err)
	}
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
            --dash-bg: #0a0a0a;
            --dash-sidebar: #141414;
            --dash-text: #ffffff;
            --dash-text-dim: #888888;
            --dash-accent: #00ffcc;
            --dash-border: rgba(255,255,255,0.1);
            --word-bg: #f3f2f1;
            --word-blue: #2b579a;
            --word-paper: #ffffff;
            --word-text: #201f1e;
            --word-border: #e1dfdd;
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
            width: 280px;
            background: var(--dash-sidebar);
            border-right: 1px solid var(--dash-border);
            padding: 30px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .dash-logo {
            font-size: 24px;
            font-weight: 700;
            color: var(--dash-accent);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .dash-btn {
            background: transparent;
            border: 1px solid var(--dash-border);
            color: var(--dash-text);
            padding: 12px 20px;
            border-radius: 12px;
            cursor: pointer;
            text-align: left;
            font-size: 14px;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .dash-btn:hover {
            border-color: var(--dash-accent);
            background: rgba(0, 255, 204, 0.05);
        }

        .dash-btn.primary {
            background: var(--dash-accent);
            color: #000;
            border: none;
            font-weight: 600;
        }

        .dash-btn.primary:hover {
            opacity: 0.9;
        }

        .dash-main {
            flex: 1;
            padding: 50px;
            overflow-y: auto;
        }

        .dash-header {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 30px;
            letter-spacing: -0.5px;
        }

        .post-list-card {
            background: var(--dash-sidebar);
            border-radius: 16px;
            border: 1px solid var(--dash-border);
            overflow: hidden;
        }

        .dash-post-item {
            padding: 20px 25px;
            border-bottom: 1px solid var(--dash-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.2s;
        }

        .dash-post-item:hover {
            background: rgba(255,255,255,0.03);
        }

        .dash-post-item:last-child {
            border-bottom: none;
        }

        .dpi-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--dash-text);
            margin-bottom: 5px;
        }

        .dpi-meta {
            font-size: 12px;
            color: var(--dash-text-dim);
            font-family: monospace;
        }

        #editor-view {
            background: var(--word-bg);
            color: var(--word-text);
            flex-direction: column;
        }

        .word-topbar {
            background: var(--word-blue);
            color: white;
            height: 48px;
            display: flex;
            align-items: center;
            padding: 0 16px;
            justify-content: space-between;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .word-back-btn {
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .word-back-btn:hover {
            background: rgba(255,255,255,0.3);
        }

        .word-ribbon {
            background: white;
            border-bottom: 1px solid var(--word-border);
            padding: 8px 20px;
            display: flex;
            gap: 10px;
        }

        .word-rib-btn {
            border: 1px solid transparent;
            background: transparent;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 5px;
            color: #555;
            transition: all 0.2s ease;
            position: relative;
        }
        
        .word-rib-btn span:first-child {
            font-size: 18px;
        }

        .word-rib-btn:hover {
            background: #e8f4ff;
            border-color: #4a90e2;
            color: #4a90e2;
            transform: translateY(-1px);
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
            background: #e8eaed;
            padding: 30px;
            overflow-y: auto;
            display: flex;
            justify-content: center;
            gap: 25px;
            align-items: flex-start;
            max-width: 100%;
        }

        .word-paper {
            width: 800px;
            max-width: 800px;
            flex-shrink: 0;
            min-height: calc(100vh - 200px);
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
            padding: 60px 80px;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            border-radius: 4px;
            position: relative;
        }
        
        .word-paper::before {
            content: '';
            position: absolute;
            top: 0;
            left: 80px;
            width: 2px;
            height: 100%;
            background: #ffeaea;
            opacity: 0.3;
        }

        .meta-panel {
            width: 360px;
            min-width: 360px;
            max-width: 360px;
            flex-shrink: 0;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            padding: 25px;
            box-sizing: border-box;
            border-radius: 4px;
            max-height: calc(100vh - 200px);
            overflow-y: auto;
            position: sticky;
            top: 30px;
            border: 1px solid #e0e0e0;
            transition: all 0.3s ease;
        }
        
        .meta-panel:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.12);
        }

        #comments-panel {
            width: 360px !important;
            min-width: 360px !important;
            max-width: 360px !important;
            flex-shrink: 0 !important;
            background: white !important;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08) !important;
            padding: 25px !important;
            box-sizing: border-box !important;
            border-radius: 4px !important;
            max-height: calc(100vh - 200px) !important;
            overflow-y: auto !important;
            position: sticky !important;
            top: 30px !important;
            border: 1px solid #ffa726 !important;
            border-left: 4px solid #ffa726 !important;
            transition: all 0.3s ease !important;
        }

        #comments-panel.show {
            display: block !important;
        }

        #comments-panel.hide {
            display: none !important;
        }

        .meta-panel h3 {
            margin: 0 0 20px 0;
            font-size: 16px;
            color: #333;
            border-bottom: 2px solid #f0f0f0;
            padding-bottom: 10px;
        }

        .meta-section {
            margin-bottom: 25px;
        }

        .meta-section label {
            display: block;
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
            font-weight: 500;
        }

        .meta-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
            font-family: var(--font-main);
        }

        .meta-input:focus {
            outline: none;
            border-color: var(--word-blue);
        }

        .tag-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 10px;
            min-height: 34px;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 6px;
            background: #fafafa;
        }

        .tag-item {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--word-blue);
            color: white;
            padding: 5px 12px;
            border-radius: 16px;
            font-size: 12px;
            font-weight: 500;
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
        }

        .tag-input-row button {
            padding: 8px 16px;
            background: var(--word-blue);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
        }

        .tag-input-row button:hover {
            opacity: 0.9;
        }

        .meta-checkbox {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 8px;
        }

        .meta-checkbox input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .meta-checkbox label {
            margin: 0;
            cursor: pointer;
        }

        .wp-title {
            font-family: 'Sitka Small', serif;
            font-size: 32px;
            font-weight: 700;
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
            margin-bottom: 30px;
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
            border: none;
            resize: none;
            outline: none;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 15px;
            line-height: 1.8;
            color: #2c3e50;
            padding: 0;
            tab-size: 4;
        }
        
        #editor-textarea::selection {
            background: rgba(74, 144, 226, 0.3);
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

    <script>
        let postsData = [];
        let currentDocPath = '';
        let commentStatsData = null;

        function switchView(view) {
            document.querySelectorAll('.view-section').forEach(e => e.classList.remove('active'));
            document.getElementById(view + '-view').classList.add('active');
            if (view === 'dashboard') {
                fetchPosts();
                fetchCommentStats();
            } else if (view === 'pending-comments') {
                loadPendingComments();
                loadCommentSettings();
            }
        }

        async function fetchCommentStats() {
            try {
                const res = await fetch('/api/comment_stats');
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
                    
                    html += '<button onclick="openEditor(\'' + zhPath + '\', \'' + zhTitle + '\', \'' + versions.zh.date + '\')" style="background:rgba(255,165,0,0.1); border:1px solid rgba(255,165,0,0.3); color:#ffa500; padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;">编辑中文</button>' +
                            '<button onclick="openEditor(\'' + enPath + '\', \'' + enTitle + '\', \'' + versions.en.date + '\')" style="background:rgba(80,200,120,0.1); border:1px solid rgba(80,200,120,0.3); color:#50c878; padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;">编辑英文</button>';
                }
                
                html += '<button onclick="deleteDocument(\'' + escapedPath + '\')" style="background:rgba(255,50,50,0.1); border:1px solid rgba(255,50,50,0.2); color:#ff5555; width:32px; height:32px; border-radius:8px; cursor:pointer;">🗑</button>' +
                        '<button onclick="openEditor(\'' + escapedPath + '\', \'' + primaryVersion.title.replace(/'/g, "\\'") + '\', \'' + primaryVersion.date + '\')" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:#fff; width:32px; height:32px; border-radius:8px; cursor:pointer;">✎</button>' +
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
                const res = await fetch('/api/get_content?path=' + encodeURIComponent(path));
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
                newFm = newFm.replace(/title:\s*["']?[^"'\n]+["']?/, 'title: "' + currentMetadata.title + '"');
            }

            // 更新date (转换为Hugo格式)
            if (currentMetadata.date) {
                const hugoDate = currentMetadata.date + ':00+08:00';
                newFm = newFm.replace(/date:\s*[\w\-:+]+/, 'date: ' + hugoDate);
            }
            
            // 更新categories
            if (currentMetadata.categories.length > 0) {
                const catYaml = 'categories:\n' + currentMetadata.categories.map(c => '    - ' + c).join('\n');
                newFm = newFm.replace(/categories:.*?(?=\n[a-z]|\n---)/s, catYaml);
                if (!newFm.includes('categories:')) {
                    newFm = newFm.replace(/---\n/, '---\n' + catYaml + '\n');
                }
            } else {
                newFm = newFm.replace(/categories:.*?(?=\n[a-z]|\n---)/s, '');
            }

            // 更新tags
            if (currentMetadata.tags.length > 0) {
                const tagYaml = 'tags:\n' + currentMetadata.tags.map(t => '    - ' + t).join('\n');
                newFm = newFm.replace(/tags:.*?(?=\n[a-z]|\n---)/s, tagYaml);
                if (!newFm.includes('tags:')) {
                    newFm = newFm.replace(/---\n/, '---\n' + tagYaml + '\n');
                }
            } else {
                newFm = newFm.replace(/tags:.*?(?=\n[a-z]|\n---)/s, '');
            }

            // 更新description
            if (currentMetadata.description) {
                newFm = newFm.replace(/description:.*?\n/, 'description: "' + currentMetadata.description + '"\n');
                if (!newFm.includes('description:')) {
                    newFm = newFm.replace(/---\n/, '---\ndescription: "' + currentMetadata.description + '"\n');
                }
            }

            // 更新image
            if (currentMetadata.image) {
                newFm = newFm.replace(/image:.*?\n/, 'image: "' + currentMetadata.image + '"\n');
                if (!newFm.includes('image:')) {
                    newFm = newFm.replace(/---\n/, '---\nimage: "' + currentMetadata.image + '"\n');
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
                const res = await fetch('/api/save_content', {
                    method: 'POST',
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
                        const syncRes = await fetch('/api/sync_translate', {
                            method: 'POST',
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
                const res = await fetch('/api/delete_post', {
                    method: 'POST',
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
                const res = await fetch('/api/create_sync', {
                    method: 'POST',
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
                const res = await fetch('/api/command?name=' + cmd);
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
                const res = await fetch('/api/all_comments?path=' + encodeURIComponent(postPath));
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
                const res = await fetch('/api/approve_comment', {
                    method: 'POST',
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
                const res = await fetch('/api/delete_comment', {
                    method: 'POST',
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
                const res = await fetch('/api/pending_comments');
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
                const res = await fetch('/api/bulk_comments', {
                    method: 'POST',
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
                const res = await fetch('/api/bulk_comments', {
                    method: 'POST',
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

        function exportCommentsCsv() {
            window.open('/api/export_comments', '_blank');
        }

        async function loadCommentSettings() {
            try {
                const res = await fetch('/api/comment_settings');
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
                const res = await fetch('/api/save_comment_settings', {
                    method: 'POST',
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
                const res = await fetch('/api/approve_comment', {
                    method: 'POST',
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
                const res = await fetch('/api/delete_comment', {
                    method: 'POST',
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
