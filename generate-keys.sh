#!/usr/bin/env bash

# WangScape Writer 密钥和证书生成脚本
# 用于生成部署所需的所有密钥、证书和哈希值

set -e

echo "========================================="
echo "WangScape Writer 密钥生成工具"
echo "========================================="
echo ""

# 生成JWT密钥
echo "[1/3] 生成JWT密钥..."
JWT_SECRET=$(openssl rand -hex 32)
echo "✓ JWT_SECRET: $JWT_SECRET"
echo ""

# 生成SMTP加密密钥
echo "[2/3] 生成SMTP加密密钥..."
SMTP_ENCRYPTION_KEY=$(openssl rand -hex 16)
echo "✓ SMTP_ENCRYPTION_KEY: $SMTP_ENCRYPTION_KEY"
echo ""

# 生成管理员密码哈希
echo "[3/3] 生成管理员密码哈希..."
echo "请输入管理员密码 (将生成SHA-256哈希):"
read -s ADMIN_PASSWORD
echo "确认密码:"
read -s ADMIN_PASSWORD_CONFIRM

if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
    echo "❌ 密码不匹配！"
    exit 1
fi

ADMIN_PASSWORD_HASH=$(echo -n "$ADMIN_PASSWORD" | sha256sum | awk '{print $1}')
echo "✓ ADMIN_PASSWORD_HASH: $ADMIN_PASSWORD_HASH"
echo ""

# 生成输出
echo "========================================="
echo "生成的密钥配置"
echo "========================================="
echo ""
echo "将以下内容添加到 .env 文件:"
echo ""
echo "# JWT配置"
echo "JWT_SECRET=$JWT_SECRET"
echo ""
echo "# 邮件配置"
echo "SMTP_ENCRYPTION_KEY=$SMTP_ENCRYPTION_KEY"
echo ""
echo "# 管理员密码配置 (二选一)"
echo "# 方式1: 明文密码"
echo "# ADMIN_PASSWORD=$ADMIN_PASSWORD"
echo ""
echo "# 方式2: 哈希密码 (推荐用于生产环境)"
echo "ADMIN_PASSWORD_HASH=$ADMIN_PASSWORD_HASH"
echo ""

# 保存到文件
OUTPUT_FILE="generated-keys-$(date +%Y%m%d-%H%M%S).txt"
cat > "$OUTPUT_FILE" << EOF
WangScape Writer - 生成的密钥配置
生成时间: $(date)

JWT_SECRET=$JWT_SECRET

SMTP_ENCRYPTION_KEY=$SMTP_ENCRYPTION_KEY

ADMIN_PASSWORD_HASH=$ADMIN_PASSWORD_HASH

使用说明:
1. 将上述值添加到 .env 文件
2. 确保 .env 文件权限为 0600 (仅owner可读)
3. 生产环境强烈建议使用 ADMIN_PASSWORD_HASH 而不是明文密码
4. 定期更换 JWT_SECRET 和 SMTP_ENCRYPTION_KEY (建议每30天一次)

TLS/HTTPS证书生成:
如需启用HTTPS，执行以下命令 (使用Let's Encrypt):
  sudo certbot certonly --standalone -d yourdomain.com
  
然后在 .env 中设置:
  TLS_CERT_FILE=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
  TLS_KEY_FILE=/etc/letsencrypt/live/yourdomain.com/privkey.pem
EOF

echo "✓ 详细信息已保存到: $OUTPUT_FILE"
echo ""
echo "========================================="
echo "下一步:"
echo "1. 复制 .env.example 为 .env"
echo "2. 编辑 .env 文件，添加上述生成的密钥"
echo "3. 设置文件权限: chmod 600 .env"
echo "4. 启动应用程序"
echo "========================================="
