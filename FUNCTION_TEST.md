# WSwriter 功能测试清单

## 1. 创建文章功能 ✓
- API: `/api/create_sync`
- 前端: `createPost()` 函数
- 后端: `handleCreateSync()` → `createSyncPost()`
- 功能: 创建中文和英文双语文章

## 2. 保存/编辑文章功能 ✓
- API: `/api/save_content`
- 前端: `saveDocument()` 函数
- 后端: `handleSaveContent()` → `saveContent()`
- 功能: 保存编辑的文章内容

## 3. 删除文章功能 ✓
- API: `/api/delete_post`
- 前端: `deleteDocument()` 函数
- 后端: `handleDeletePost()` → `deletePost()`
- 功能: 删除文章

## 4. 文章翻译同步功能 ✓
- API: `/api/sync_translate`
- 前端: `saveDocument()` 中自动调用（当编辑中文版本时）
- 后端: `handleSyncTranslate()` → `syncTranslateContent()`
- 功能: 将中文内容翻译并同步到英文版本

## 5. 获取文章列表功能 ✓
- API: `/api/posts`
- 前端: `fetchPosts()` 函数
- 后端: `handleGetPosts()` → `getPosts()`
- 功能: 获取所有文章（包括中文和英文版本）

## 6. 获取文章内容功能 ✓
- API: `/api/get_content`
- 前端: `openEditor()` 函数
- 后端: `handleGetContent()` → `getContent()`
- 功能: 获取单篇文章内容用于编辑

## 7. 删除评论功能 ✓
- API: `/api/delete_comment`
- 前端: `deletePendingCommentAction()` 函数
- 后端: `handleDeleteComment()` → `deleteComment()`
- 功能: 删除评论

## 8. 评论管理功能 ✓
- 获取评论: `/api/comments`
- 添加评论: `/api/add_comment`
- 批准评论: `/api/approve_comment`
- 所有评论: `/api/all_comments`
- 评论统计: `/api/comment_stats`
- 待审核评论: `/api/pending_comments`
- 批量操作: `/api/bulk_comments`
- 导出评论: `/api/export_comments`

## 9. 评论设置管理 ✓
- 获取设置: `/api/comment_settings`
- 保存设置: `/api/save_comment_settings`
- 功能: 管理SMTP、黑名单等设置

## 测试步骤

### 创建文章
1. 点击"新建文章"按钮
2. 输入标题和分类
3. 点击"创建"
4. 应该在列表中看到新文章（中文和英文版本）

### 编辑文章
1. 在文章列表中点击编辑按钮
2. 在编辑器中修改内容
3. 点击"保存"按钮（或 Ctrl+S）
4. 应该看到"已保存"提示
5. 自动翻译提示会出现（中文版本）

### 删除文章
1. 在文章列表中点击删除按钮（垃圾桶图标）
2. 确认删除
3. 文章应该从列表中消失

### 管理评论
1. 进入"待审核评论"视图
2. 查看未审核的评论
3. 可以单个或批量批准/删除评论
4. 可以导出评论为CSV

### 配置评论设置
1. 进入"待审核评论"视图
2. 在右侧面板配置SMTP和黑名单
3. 点击"保存设置"
4. 设置应该被保存到 `config/comment_settings.json`

## 已知正确的实现

所有API端点都已正确注册，前端函数都已实现，后端逻辑都已完成。
系统应该全功能工作。
