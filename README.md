<palign="right">
  <a href="README.en.md" style="font-size:1.1em;font-weight:bold;text-decoration:none;">🇬🇧 English Version</a>
</p>

# Hugo 博客项目

<palign="center">
  <img src="https://gohugo.io/images/hugo-logo-wide.svg" alt="Hugo Logo" width="300" />
</p>

> 🚀 基于 [hugo-theme-stack](https://github.com/CaiJimmy/hugo-theme-stack) 的多语言静态博客，支持自定义布局、分析、现代美观 UI。

---

## 📋 项目亮点

- 🌍 多语言支持（中文、英文）
- 🎨 现代卡片风格主题，响应式设计
- 🧩 支持自定义侧边栏、页脚、分析（如 Umami）
- 🧮 数学公式、图片画廊、全文搜索、归档等功能
- 📝 Markdown、短代码、数学排版
- ⚡️ 一键生成新文章/页面模板
- 🐞 本地实时预览与调试
- 🚚 支持多平台静态部署

## 📁 目录结构

- `content/`：博客内容（文章、分类、标签等）
- `config/`：站点配置（多语言、菜单、参数等）
- `theme/`：主题相关文件
- `public/`：生成的静态页面（可部署）
- `static/`：静态资源（图片、样式等）
- `assets/`：自定义样式与脚本

## 🏁 快速开始

1. 安装 [Hugo](https://gohugo.io/getting-started/installing/)
2. 克隆本仓库
3. 在项目根目录运行：
   ```bash
   hugo server -D
   ```
4. 访问本地预览：`http://localhost:1313`

## ⚡️ 快速生成新文章/模板

使用 Hugo 命令一键生成新文章或页面模板：

- 生成新文章：
  ```bash
  hugo new zh-cn/post/你的文章名/index.md
  ```
  或英文：
  ```bash
  hugo new en/post/your-article/index.md
  ```
  自动创建带基础 front matter 的 Markdown 文件。

- 生成新页面（如归档、链接页等）：
  ```bash
  hugo new zh-cn/page/archives/index.md
  ```

> 生成后可直接编辑内容，支持自定义分类、标签、摘要等。

## 🎨 主题与自定义

- 主题：Stack（现代卡片风格，响应式设计）
- 多语言支持：中文、英文
- 可自定义侧边栏、页脚、分析（如 Umami）
- 支持数学公式、图片画廊、搜索、归档等功能
- 文章支持 Markdown、短代码、数学排版

## 🐞 调试与开发

- 本地实时预览（推荐开发/调试时使用） ：
  ```bash
  hugo server -D
  ```
  - 自动监听文件变更，实时刷新浏览器。
  - `-D` 参数会显示草稿（draft）文章。
  - 默认访问地址：`http://localhost:1313`

- 检查配置与内容错误：
  - Hugo 启动时如遇报错，请检查 `config/` 配置文件和内容 front matter 格式。
  - 可用 VS Code 或其他编辑器配合 Markdown/Linter 插件辅助检查。

- 常见调试技巧：
  - 逐步注释/还原配置项，定位问题。
  - 使用 `hugo --verbose` 查看详细日志。
  - 清理缓存/输出目录：
    ```bash
    hugo --cleanDestinationDir
    ```
    或手动删除 `public/` 目录后重新生成。

- 主题/布局调试：
  - 修改 `layouts/` 或 `theme/` 下的模板文件后，刷新页面即可看到效果。
  - 可用浏览器开发者工具（F12）检查样式和 DOM 结构。

## 🚚 部署

生成静态文件：
```bash
hugo
```
将 `public/` 目录内容部署到任意静态网站托管平台：
- GitHub Pages
- Vercel
- Netlify
- 腾讯云/阿里云对象存储

## 💡 常见问题

- 如何添加新文章？
  > 在 `content/zh-cn/post/` 或 `content/en/post/` 下新建文件夹和 `index.md`，参考已有内容。
- 如何更换主题？
  > 替换 `theme/` 目录内容，并在 `config.toml` 中指定主题。
- 如何添加自定义样式？
  > 在 `assets/scss/custom.scss` 中编写自定义 CSS。

## 🤝 贡献方式

欢迎提交 Issue 或 PR 改进本博客！
- 修复 bug
- 优化样式
- 增加新功能

## 📜 许可证

MIT License

---

> 本项目由 [Hugo](https://gohugo.io/) 强力驱动，主题 [Stack](https://github.com/CaiJimmy/hugo-theme-stack) 设计自 Jimmy Cai。

## 🖱️ 一键切换英文版 README

你可以直接在 VS Code 终端或 PowerShell 中运行如下命令一键切换：

```powershell
./switch-readme.ps1 en   # 切换为英文版 README
./switch-readme.ps1 zh   # 切换为中文版 README
```

> 脚本会自动交换 README.md 与 README.en.md 的内容，无需手动重命名。

如未找到脚本，请确认项目根目录有 `switch-readme.ps1` 文件。

---

如需英文说明，请查看或重命名 `README.en.md` 文件：

- 直接浏览：`README.en.md`
- 或将其重命名为 `README.md` 以在 GitHub 默认显示英文版

---
