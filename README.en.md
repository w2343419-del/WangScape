# WangScape (Hugo Blog + WSwriter)

[![Hugo](https://img.shields.io/badge/Hugo-Extended-blueviolet?style=flat-square)](https://gohugo.io/)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

A Hugo-based personal blog with a Go writing tool **WSwriter**. It supports local authoring, static publishing, and a GitHub Issues–based comment workflow (approve before display).

## Highlights

- **Writing tool**: local editor, fast publish, bilingual content
- **Static site**: Hugo build, lightweight and fast
- **Comments**: GitHub Issues as a public inbox (moderation first)
- **Security**: no public comment backend exposed

## Quick Start

### Run WSwriter

- Windows: run WSwriter.exe
- macOS/Linux: run ./WSwriter

Open http://localhost:8080 to start writing.

### Local Preview

```
hugo server
```

Visit http://localhost:1313.

## Comment Workflow (GitHub Issues)

This project uses **“submit → issue → approve → display”**:

1) Visitors submit a comment (opens a GitHub Issue with labels `comment` + `pending`)
2) You approve by adding the `approved` label
3) The site only renders issues labeled `comment` + `approved`

### Required Config

Set the repo in [config/_default/params.toml](config/_default/params.toml):

```
[params]
    githubCommentsRepo = "w2343419-del/WangScape"
```

Default labels:
- `comment`
- `pending`
- `approved`

## Structure

```
content/              # Posts
assets/               # JS/SCSS
config/               # Hugo config
layouts/              # Theme overrides
static/               # Static assets
WSwriter.go           # Writing tool source
WSwriter.exe          # Writing tool (Windows)
```

## Build WSwriter

```
go build -o WSwriter.exe WSwriter.go
```

## License

MIT License - see [LICENSE](LICENSE)
