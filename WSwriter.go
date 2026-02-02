package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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
}

// Frontmatter represents post metadata
type Frontmatter struct {
	Title      string
	Draft      bool
	Date       string
	Categories []string
}

// APIResponse is a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Content string      `json:"content,omitempty"`
	Data    interface{} `json:"data,omitempty"`
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
		})

		return nil
	})

	// Sort by date descending, limit to 50
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date > posts[j].Date
	})

	if len(posts) > 50 {
		posts = posts[:50]
	}

	return posts
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
		// 先构建一次，确保所有内容都是最新的
		buildCmd := exec.Command("hugo")
		buildCmd.Dir = hugoPath
		if err := buildCmd.Run(); err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("Build failed: %v", err)}, err
		}
		
		// 启动预览服务器
		go func() {
			cmd := exec.Command("hugo", "server", "--disableFastRender", "--bind", "127.0.0.1", "--navigateToChanged")
			cmd.Dir = hugoPath
			cmd.Run()
		}()
		time.Sleep(2 * time.Second) // 等待服务器启动
		return map[string]interface{}{
			"message": "Server launched",
			"url":     "http://localhost:1313/WangScape/",
		}, nil

	case "deploy":
		cmd := exec.Command("git", "add", ".")
		cmd.Dir = hugoPath
		cmd.Run()

		cmd = exec.Command("git", "commit", "-m", "Web Update")
		cmd.Dir = hugoPath
		cmd.Run()

		cmd = exec.Command("git", "push")
		cmd.Dir = hugoPath
		if err := cmd.Run(); err != nil {
			return map[string]interface{}{"message": fmt.Sprintf("Deploy failed: %v", err)}, err
		}

		return map[string]interface{}{"message": "Deployed successfully"}, nil

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
	http.HandleFunc("/api/command", handleCommandAPI)

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
            padding: 6px 12px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 13px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            color: #333;
        }

        .word-rib-btn:hover {
            background: #f0f0f0;
            border-color: #d0d0d0;
        }

        .word-workspace {
            flex: 1;
            display: flex;
            overflow: hidden;
        }

        .word-canvas {
            flex: 1;
            background: #f3f3f3;
            padding: 40px;
            overflow-y: auto;
            display: flex;
            justify-content: center;
        }

        .word-paper {
            width: 800px;
            min-height: 1000px;
            background: white;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            padding: 60px 80px;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
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
            height: 800px;
            border: none;
            resize: none;
            outline: none;
            font-family: 'Inter', monospace;
            font-size: 15px;
            line-height: 1.6;
            color: #333;
            padding: 0;
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
            <button class="dash-btn" onclick="location.reload()">🔄 刷新列表</button>
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

    <div id="editor-view" class="view-section">
        <div class="word-topbar">
            <div style="display:flex; align-items:center; gap:15px;">
                <button class="word-back-btn" onclick="switchView('dashboard')">← 返回仪表盘</button>
                <strong style="font-size:16px;">WangScape Writer</strong>
            </div>
            <div>
                <span id="current-doc-name" style="opacity:0.8; margin-right:20px; font-size:13px;"></span>
                <span id="save-status" style="font-size:12px; margin-right:15px; color:#ddd;"></span>
            </div>
        </div>
        <div class="word-ribbon">
            <button class="word-rib-btn" onclick="saveDocument()"><span>💾 Save</span></button>
            <button class="word-rib-btn" onclick="runCommand('deploy')"><span>🚀 Publish</span></button>
            <button class="word-rib-btn" onclick="runCommand('preview')"><span>👁 Preview Site</span></button>
            <button class="word-rib-btn" onclick="insertCodeBlock()"><span>💻 Code Block</span></button>
            <button class="word-rib-btn" onclick="insertImage()"><span>🖼 Image</span></button>
        </div>
        <div class="word-workspace">
            <div class="word-canvas">
                <div class="word-paper" id="paper-content">
                    <div style="text-align:center; color:#999; margin-top:100px;">
                        请选择左侧文章进行编辑
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal-overlay" id="create-modal">
        <div class="modal-card">
            <h2 style="margin-top:0">创作新篇章</h2>
            <label>文章标题 (中文)</label>
            <input type="text" id="postTitle" placeholder="例如：冬日随笔">
            <label>分类 (Categories)</label>
            <input type="text" id="postCat" placeholder="Life, Code">
            <p style="font-size:12px; color:var(--dash-text-dim)">* 系统将自动生成双语版本 (zh-cn/en)。</p>
            <div style="text-align:right">
                <button class="btn-cancel" onclick="closeCreateModal()">取消</button>
                <button class="btn-confirm" onclick="createPost()">立即创建</button>
            </div>
        </div>
    </div>

    <script>
        let postsData = [];
        let currentDocPath = '';

        function switchView(view) {
            document.querySelectorAll('.view-section').forEach(e => e.classList.remove('active'));
            document.getElementById(view + '-view').classList.add('active');
            if (view === 'dashboard') fetchPosts();
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
            list.innerHTML = postsData.map(p => {
                // 转义路径中的反斜杠用于 JavaScript
                const escapedPath = p.path.replace(/\\/g, '\\\\');
                return '<div class="dash-post-item">' +
                    '<div onclick="openEditor(\'' + escapedPath + '\', \'' + p.title.replace(/'/g, "\\'") + '\', \'' + p.date + '\')" style="flex:1; cursor:pointer; display:flex; flex-direction:column; gap:4px;">' +
                    '<div style="display:flex; align-items:center; gap:10px;">' +
                    '<div class="dpi-title">' + p.title + '</div>' +
                    '<span style="font-size:10px; padding:2px 6px; border-radius:4px; background:' + p.status_color + '20; color:' + p.status_color + ';">' +
                    p.status +
                    '</span>' +
                    '</div>' +
                    '<div class="dpi-meta">' + p.date + ' · ' + p.lang.toUpperCase() + ' · ' + p.path + '</div>' +
                    '</div>' +
                    '<div style="display:flex; gap:15px; align-items:center;">' +
                    '<button onclick="deleteDocument(\'' + escapedPath + '\')" style="background:rgba(255,50,50,0.1); border:1px solid rgba(255,50,50,0.2); color:#ff5555; width:32px; height:32px; border-radius:8px; cursor:pointer;">🗑</button>' +
                    '<button onclick="openEditor(\'' + escapedPath + '\', \'' + p.title.replace(/'/g, "\\'") + '\', \'' + p.date + '\')" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:#fff; width:32px; height:32px; border-radius:8px; cursor:pointer;">✎</button>' +
                    '</div>' +
                    '</div>';
            }).join('');
        }

        async function openEditor(path, title, date) {
            currentDocPath = path;
            switchView('editor');
            document.getElementById('current-doc-name').textContent = title;
            const paper = document.getElementById('paper-content');
            paper.innerHTML = '<div style="text-align:center; margin-top:50px; color:#888;">加载中...</div>';

            try {
                const res = await fetch('/api/get_content?path=' + encodeURIComponent(path));
                const data = await res.json();
                paper.innerHTML = '<div class="wp-title">' + title + '</div>' +
                    '<div style="font-size:12px; color:#999; margin-bottom:20px;">Date: ' + date + '</div>' +
                    '<textarea id="editor-textarea" spellcheck="false">' + data.content + '</textarea>';
            } catch(e) {
                paper.innerHTML = '<div style="color:red">Error: ' + e + '</div>';
            }
        }

        async function saveDocument() {
            if(!currentDocPath) return;
            const content = document.getElementById('editor-textarea').value;
            const statusEl = document.getElementById('save-status');
            statusEl.textContent = "保存中...";

            try {
                const res = await fetch('/api/save_content', {
                    method: 'POST',
                    body: JSON.stringify({ path: currentDocPath, content: content })
                });
                const data = await res.json();
                if(data.success) {
                    statusEl.textContent = "已保存 " + new Date().toLocaleTimeString();
                    setTimeout(() => statusEl.textContent = "", 3000);
                    fetchPosts();
                } else {
                    alert("保存失败: " + data.message);
                }
            } catch(e) {
                alert("错误: " + e);
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
                    fetchPosts();
                } else {
                    alert("删除失败: " + data.message);
                }
            } catch(e) {
                alert("错误: " + e);
            }
        }

        function openCreateModal() {
            document.getElementById('create-modal').style.display = 'flex';
        }

        function closeCreateModal() {
            document.getElementById('create-modal').style.display = 'none';
        }

        async function createPost() {
            const title = document.getElementById('postTitle').value;
            const cat = document.getElementById('postCat').value;
            if(!title) return alert('需要输入标题');

            try {
                const res = await fetch('/api/create_sync', {
                    method: 'POST',
                    body: JSON.stringify({ title, categories: cat })
                });
                const data = await res.json();
                if(data.success) {
                    closeCreateModal();
                    await fetchPosts();
                    alert('创建成功！');
                } else {
                    alert('错误: ' + data.message);
                }
            } catch(e) {
                alert('错误: ' + e);
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
            
            const codeBlock = '\x60\x60\x60' + language + '\\n' + (selectedText || '// 在这里输入代码\\n') + '\\n\x60\x60\x60\\n';
            
            textarea.value = textarea.value.substring(0, start) + codeBlock + textarea.value.substring(end);
            
            const newCursorPos = start + language.length + 4;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            textarea.focus();
        }

        function insertImage() {
            const textarea = document.getElementById('editor-textarea');
            if(!textarea) return;

            const imageUrl = prompt('请输入图片 URL 或路径\\n(例如: /img/photo.jpg 或 https://example.com/image.png):', '');
            if(!imageUrl) return;

            const altText = prompt('请输入图片描述 (可选):', '图片');
            const width = prompt('图片宽度 (如: 500px, 80%, 留空为原始大小):', '');
            const align = prompt('对齐方式\\n输入: left (左对齐), center (居中), right (右对齐)\\n留空为默认', 'center');
            
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            
            let imageHtml = '<div style="text-align: ' + (align || 'center') + ';">\\n';
            imageHtml += '  <img src="' + imageUrl + '" alt="' + (altText || '图片') + '"';
            if(width) {
                imageHtml += ' style="width: ' + width + '; height: auto;"';
            }
            imageHtml += '>\\n';
            imageHtml += '</div>\\n\\n';
            
            textarea.value = textarea.value.substring(0, start) + imageHtml + textarea.value.substring(end);
            
            const newCursorPos = start + imageHtml.length;
            textarea.setSelectionRange(newCursorPos, newCursorPos);
            textarea.focus();
        }

        async function runCommand(cmd) {
            const res = await fetch('/api/command?name=' + cmd);
            const data = await res.json();
            if(data.data && data.data.url) {
                window.open(data.data.url, '_blank');
            } else {
                alert('系统: ' + (data.message || data.data?.message || '命令已执行'));
            }
        }

        fetchPosts();
    </script>
</body>
</html>`
