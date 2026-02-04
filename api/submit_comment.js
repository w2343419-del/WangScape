module.exports = async (req, res) => {
  // CORS headers
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS,PATCH,DELETE,POST,PUT");
  res.setHeader("Access-Control-Allow-Headers", "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version");
  
  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  // Debug: 接受GET请求用于测试
  if (req.method === "GET") {
    res.status(200).json({ success: true, message: "API正常运行", version: "1.0" });
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ success: false, message: "仅支持POST请求" });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (err) {
      res.status(400).json({ success: false, message: "无效的请求数据" });
      return;
    }
  }

  const {
    post_path,
    post_title,
    author,
    email,
    content,
    parent_id,
    use_github,
    github_repo,
    github_labels,
  } = body || {};

  if (!author || !email || !content || !post_path) {
    res.status(400).json({ success: false, message: "缺少必填字段" });
    return;
  }

  if (!use_github || !github_repo) {
    res.status(501).json({ success: false, message: "当前仅支持GitHub评论" });
    return;
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    res.status(500).json({ success: false, message: "未配置GitHub Token" });
    return;
  }

  const title = `[Comment] ${post_title || post_path}`;
  const bodyLines = [
    `Post: ${post_path}`,
    `Author: ${author}`,
    `Email: ${email}`,
  ];
  if (parent_id) bodyLines.push(`Parent ID: ${parent_id}`);
  bodyLines.push("", "Content:", content);

  const issue = {
    title,
    body: bodyLines.join("\n"),
    labels: Array.isArray(github_labels) ? github_labels : [],
  };

  try {
    const ghRes = await fetch(`https://api.github.com/repos/${github_repo}/issues`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "User-Agent": "comment-api",
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(issue),
    });

    if (ghRes.status !== 201) {
      const text = await ghRes.text();
      res.status(500).json({
        success: false,
        message: `提交到GitHub失败: ${text}`,
      });
      return;
    }

    res.status(200).json({
      success: true,
      message: "评论已提交到GitHub，等待审核后将显示在页面上",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: `提交失败: ${err}` });
  }
}
