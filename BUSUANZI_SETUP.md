# 卜算子 (Busuanzi) 访问统计完整指南

> **方案**：卜算子（不蒜子） - 开源、免费、无需后端的网站统计  
> **特点**：纯前端实现、无隐私问题、无服务器依赖  
> **配置**：即插即用，无需任何后端配置

---

## 📋 集成状态

✅ **已完成**：
- ✅ 集成卜算子统计脚本（https://busuanzi.ibruce.info）
- ✅ 本地页面阅读量统计（基于 localStorage）
- ✅ 移除 Umami 和 Supabase 依赖
- ✅ 适配 GitHub Pages 托管场景

---

## 📊 卜算子功能说明

### 提供的统计指标

| 指标 | 说明 | 使用方式 |
|------|------|--------|
| 站点总访问量 | 所有页面的 PV 总和 | `<span id="busuanzi_value_site_pv"></span>` |
| 站点总访客数 | 唯一访客 UV (基于 IP) | `<span id="busuanzi_value_site_uv"></span>` |
| 页面访问量 | 单页面 PV | `<span id="busuanzi_value_page_pv"></span>` |
| 页面访客数 | 单页面 UV | `<span id="busuanzi_value_page_uv"></span>` |

### 本项目中的实现

**本项目结合了两种统计方式**：

1. **卜算子统计**：
   - 自动加载卜算子脚本
   - 提供全站访问量总计
   - 跨浏览器、跨会话统计（基于 IP）

2. **本地页面阅读量**：
   - 基于浏览器 localStorage
   - 本地计数，不依赖远程服务
   - 用户清除 localStorage 后重置

---

## 💻 在页面中使用卜算子

### 显示网站总访问次数

```html
<!-- 页面访问次数 -->
本站总访问量：<span id="busuanzi_value_site_pv"></span> 次

<!-- 页面访客数 -->
本站总访客数：<span id="busuanzi_value_site_uv"></span> 人
```

### 显示当前页面访问量

```html
<!-- 当前页面访问次数 -->
此页面访问量：<span id="busuanzi_value_page_pv"></span> 次

<!-- 当前页面访客数 -->
此页面访客数：<span id="busuanzi_value_page_uv"></span> 人
```

---

## 🔍 工作原理

### 加载流程

1. 页面加载时，自动加载卜算子脚本：
   ```javascript
   https://busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js
   ```

2. 卜算子脚本扫描页面中 ID 为 `busuanzi_value_*` 的元素

3. 自动填充统计数据到相应元素

### 本地页面阅读量逻辑

- 文章详情页首次打开时，`incrementPageViews()` 递增计数
- 阅读量保存到 `localStorage` 中，键格式：`page_views__p_article_name`
- 列表页显示每篇文章的本地统计阅读量
- 用户清除 localStorage 后重置（浏览器菜单或开发者工具）

---

## ✨ 优势对比

### 卜算子 vs 传统统计方案

| 方案 | 部署复杂性 | 隐私 | 成本 | 可靠性 |
|------|---------|------|------|--------|
| **卜算子** | ✅ 极简（无后端） | ✅ 完全本地 | ✅ 免费 | ✅ 社区活跃 |
| Umami | ⚠️ 需要数据库与服务端部署 | ⚠️ 需信任服务商 | ⚠️ 持续维护成本 | ⚠️ 有运维复杂度 |
| 百度统计 | ✅ 简单 | ❌ 数据上报 | ⚠️ 有限免费 | ✅ 稳定 |
| GA | ✅ 简单 | ❌ 数据上报 | ⚠️ 有限免费 | ✅ 功能完备 |

---

## 🚀 本地测试

### 开发环境

```bash
# 启动 Hugo 本地预览
hugo server

# 访问
http://localhost:1313
```

**本地测试说明**：
- ✅ 本地页面阅读量统计正常工作（基于 localStorage）
- ⚠️ 卜算子全站统计在本地 localhost 上有限制
  - 卜算子基于 IP 统计，本地环回地址 127.0.0.1 无法正常统计
  - **解决方案**：使用本机 IP 访问（如 `http://192.168.x.x:1313`）或部署到线上域名后完全生效

### 生产环境

部署到任何支持静态网站的平台后，卜算子统计会完全生效：

- ✅ 全站访问量统计
- ✅ 全站访客数统计  
- ✅ 页面级别统计

---

## 📝 自定义扩展

### 添加卜算子到其他模板

在任何模板中添加卜算子展示元素：

```html
<footer class="site-statistics">
  <span>本站访问：<span id="busuanzi_value_site_pv"></span> 次</span>
  <span>访客：<span id="busuanzi_value_site_uv"></span> 人</span>
</footer>
```

### 自定义样式

```css
#busuanzi_value_site_pv,
#busuanzi_value_site_uv {
    font-weight: bold;
    color: #0066cc;
}
```

### 监听加载完成

```javascript
// 卜算子加载完成后的回调
window.addEventListener('busuanzi-load', function() {
    console.log('卜算子统计已加载完成');
});
```

---

## 🔧 故障排除

### 问题 1：卜算子数据不显示

**可能原因**：
- 网络连接问题导致脚本加载失败
- 浏览器控制台出现 CORS 错误

**解决方案**：
```javascript
// 检查是否加载成功
console.log(window.busuanzi);  // 应该显示对象，不是 undefined

// 检查浏览器控制台是否有错误
// F12 → Console → 查看是否有红色错误信息
```

### 问题 2：本地页面阅读量不更新

**原因**：
- 可能清除了浏览器 localStorage
- 或在浏览器无痕模式下使用

**解决方案**：
- 确保浏览器允许 localStorage
- 在现代浏览器的普通窗口中打开

### 问题 3：访问量数据不准确

- 卜算子基于 IP 识别，多人使用同一 IP 时可能计为同一访客
- 本地页面阅读量基于用户浏览器数据，清除 localStorage 后重置

---

## 📚 相关资源

- **卜算子官网**：https://busuanzi.ibruce.info
- **GitHub 项目**：https://github.com/ibruce/Busuanzi
- **中文文档**：https://busuanzi.ibruce.info/ （官网查看）

---

## ✅ 配置清单

- [x] 卜算子脚本已集成到 `layouts/partials/head/custom.html`
- [x] 本地页面阅读量统计已实现
- [x] `layouts/partials/article/components/details.html` 已更新为使用卜算子
- [x] 移除了 Umami + Supabase 的所有配置和依赖
- [x] 兼容 GitHub Pages 托管（无需任何后端）
- [x] 无需后端配置，即插即用

---

## 🎉 下一步

本项目已完全迁移到卜算子，您现在可以：

1. **本地开发**：使用 `hugo server` 进行本地预览
2. **部署**：无需任何额外配置，直接部署到 GitHub Pages 或其他静态网站服务
3. **监控统计**：部署后访问网站，卜算子会自动开始收集统计数据

所有统计数据都基于客户端，无隐私问题，无服务器成本！
