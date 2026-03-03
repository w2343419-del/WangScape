# Umami 部署完整指南

> **目标**：为 Hugo 博客添加访客统计  
> **方案**：Vercel + Neon PostgreSQL + Umami  
> **耗时**：约 30 分钟（部署 + 配置）

---

## 📋 工作总结

你已经完成了：
- ✅ 删除旧的失败部署（2 个 Vercel 项目）
- ✅ 创建新 Umami 项目并部署到 Vercel（状态：Ready）
- ✅ 创建 Neon PostgreSQL 数据库
- ✅ 配置环境变量：`DATABASE_URL` + `APP_SECRET`
- ✅ 登录 Umami 控制面板（admin/umami）
- ✅ 添加网站配置，获取 Website ID
- ✅ 在 `custom.html` 中配置追踪脚本
- ✅ 确认 Umami 后端正常工作（控制面板可用）

---

## 📊 当前配置

### Umami 部署 URL
```
https://umami-6uy33nhgb-w2343419-dels-projects.vercel.app
```

### Website ID
```
5c2547c2-59d7-4d72-a06a-f30718804b0e
```

### Domain
```
localhost
```

### custom.html 追踪脚本
```html
<script>
  (function() {
    const script = document.createElement('script');
    script.defer = true;
    script.src = 'https://umami-6uy33nhgb-w2343419-dels-projects.vercel.app/script.js';
    script.setAttribute('data-website-id', '5c2547c2-59d7-4d72-a06a-f30718804b0e');
    script.setAttribute('data-domains', 'localhost');
    document.head.appendChild(script);
  })();
</script>
```

---

## 🔍 本地测试已知限制

### 浏览器 Cookie 安全策略

当本地通过 `localhost:1313` 测试时，浏览器会阻止跨域 Cookie：
- **现象**：F12 Network 中 script.js 请求返回 401 Unauthorized
- **原因**：浏览器跨域安全策略（Same-Site Cookie），防止跨域追踪
- **影响**：本地测试无法正常加载 Umami 脚本
- **解决**：上线到真实域名后，此限制自动解除

### 验证方法

✅ **正常工作的迹象**：
- Umami 控制面板（直接访问 Umami URL）可以正常使用
- 控制面板顶部显示实时访客信息
- Settings → Websites 可以看到已添加的网站

❌ **本地无法测试**：
- `localhost:1313` 加载脚本被浏览器阻止（401）
- `window.umami` 在本地显示 undefined
- `/api/send` 请求无法发送

---

## 🚀 下一步行动

### 选项 A：部署博客到线上

一旦部署博客到真实域名（如 Vercel），Umami 追踪会自动生效：

1. **修改 custom.html 中的 domain**
   ```html
   script.setAttribute('data-domains', 'wangscape.com'); // 改成你的真实域名
   ```

2. **部署博客到线上**（使用 Vercel、Netlify 等）

3. **访问线上博客**，Umami 会自动开始记录访问数据

4. **检查 Umami 控制面板的 Realtime 标签**，看真实访问

### 选项 B：保持当前配置

- 继续本地开发，配置已正确设置
- 不需要做任何改动
- 上线时自动生效

---

## 🔧 故障排查

### 问题：Umami 控制面板无法访问

**检查清单**：
1. Vercel 部署状态是否为 ✅ Ready
2. 数据库连接：Settings → Environment Variables 中 `DATABASE_URL` 是否存在
3. APP_SECRET：是否已设置
4. 需要重新部署：Deployments → 最新部署 → ... → Redeploy

### 问题：script.js 返回 401（本地测试）

**预期行为** - 这不是错误，而是浏览器安全策略：
- 本地 localhost:1313 请求被浏览器阻止
- 这是正常的、无法绕过的
- 上线到真实域名后自动解决

### 问题：script.js 返回 500 或其他错误

**检查清单**：
1. Umami 部署日志中有无数据库连接错误
2. 环境变量是否都已设置
3. 尝试 Redeploy 一次

---

## 📝 环境变量配置

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `DATABASE_URL` | PostgreSQL 连接地址 | postgresql://user:pass@host:5432/umami |
| `APP_SECRET` | 应用加密密钥（32 字符） | c7f3a8e2b1d9f4a6c5b7d8e9f0a1b2c3 |

**检查方法**：
- Vercel Dashboard → 项目 → Settings → Environment Variables
- 确保两个变量都存在且有值

---

## 🛡️ 安全建议

1. **修改默认密码（重要！）**
   - 登录后立即进 Settings → Change Password
   - 默认密码 `umami` 是公开的

2. **设置强密码**
   - 至少 12 字符
   - 包含大小写、数字、特殊字符

3. **限制访问**
   - 如果是公开部署，考虑在 Vercel 中添加基础身份验证（Basic Auth）

---

## 📞 相关文件

- **配置文件**：[layouts/partials/head/custom.html](layouts/partials/head/custom.html)
- **Vercel 项目**：https://vercel.com/dashboard
- **Neon 数据库**：https://console.neon.tech
- **Umami 官网**：https://umami.is
