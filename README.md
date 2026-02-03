# WangScape（Hugo Blog + WSwriter）

[![Hugo](https://img.shields.io/badge/Hugo-Extended-blueviolet?style=flat-square)](https://gohugo.io/)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

基于 Hugo 与 Stack 主题的个人博客系统，配套 Go 写作工具 **WSwriter**。支持本地创作、静态发布，并提供基于 GitHub Issues 的安全评论流程（先审核后展示）。

## 功能概览

- **写作工具**：本地可视化编辑、快速发布、双语内容
- **静态站点**：Hugo 构建，轻量高性能
- **评论方案**：GitHub Issues 作为评论收集池（审核后才展示）
- **安全策略**：无公网评论后端暴露，避免被滥用

## 快速开始

### 运行写作工具

- Windows：运行 WSwriter.exe
- macOS/Linux：运行 ./WSwriter

浏览器打开 http://localhost:8080 即可进入写作界面。

### 本地预览站点

使用 Hugo CLI：

```
hugo server
```

访问 http://localhost:1313 预览。

## 评论流程（GitHub Issues）

默认采用 **“访客提交 → GitHub Issues → 你审核 → 站点展示”**：

1) 访客提交评论会跳转创建 Issue（自动带标签 `comment` + `pending`）
2) 你审核后给 Issue 添加 `approved` 标签
3) 站点只显示带 `comment` + `approved` 的评论

### 必填配置

在 [config/_default/params.toml](config/_default/params.toml) 配置仓库：

```
[params]
    githubCommentsRepo = "w2343419-del/WangScape"
```

可选标签配置（默认）：
- `comment`（评论标识）
- `pending`（待审）
- `approved`（已审）

## 项目结构

```
content/              # 文章内容
assets/               # 资源（JS/SCSS）
config/               # Hugo 配置
layouts/              # 主题模板覆盖
static/               # 静态资源
WSwriter.go           # 写作工具源码
WSwriter.exe          # 写作工具（Windows）
```

## 构建写作工具

```
go build -o WSwriter.exe WSwriter.go
```

## 许可

MIT License - 详见 [LICENSE](LICENSE)
