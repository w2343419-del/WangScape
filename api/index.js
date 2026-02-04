module.exports = async (req, res) => {
  // 完整的CORS配置
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Accept, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
  
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  
  if (req.method === "GET") {
    return res.json({ status: "API is alive", timestamp: new Date().toISOString() });
  }
  
  if (req.method === "POST") {
    const { post_path, post_title, author, email, content, github_repo } = req.body || {};
    
    if (!author || !email || !content || !post_path || !github_repo) {
      return res.status(400).json({ success: false, message: "缺少必填字段" });
    }

    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      return res.status(500).json({ success: false, message: "GitHub Token未配置" });
    }

    try {
      const issue = {
        title: `[Comment] ${post_title || post_path}`,
        body: `**Post:** ${post_path}\n**Author:** ${author}\n**Email:** ${email}\n\n${content}`,
        labels: ["pending", "comment"]
      };

      const ghRes = await fetch(`https://api.github.com/repos/${github_repo}/issues`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Accept": "application/vnd.github+json"
        },
        body: JSON.stringify(issue)
      });

      if (ghRes.status === 201) {
        return res.json({ success: true, message: "评论已提交，等待审核" });
      }
      
      const err = await ghRes.text();
      return res.status(500).json({ success: false, message: `GitHub: ${err}` });
    } catch (e) {
      return res.status(500).json({ success: false, message: `Error: ${e.message}` });
    }
  }
  
  res.status(405).json({ success: false, message: "Method not allowed" });
};
