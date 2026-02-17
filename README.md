# Mail Console

现代化 UI 邮箱系统，支持：
- 注册 / 登录（D1 + JWT Cookie）
- 发件（To / Cc / Bcc）
- 收件箱（已读/未读、星标、归档、搜索）
- 已发送（星标、搜索）
- 草稿箱（保存、加载、删除）
- 一键部署到 Cloudflare Worker（免费额度可用）

## 1. 依赖

```bash
npm install
```

## 2. 创建 Cloudflare 资源（免费）

1. 创建 D1 数据库
```bash
wrangler d1 create cfmail-db
```
把返回的 `database_id` 填入 `wrangler.toml`。

2. 创建 R2 bucket（保存邮件原文）
```bash
wrangler r2 bucket create cfmail-raw
```

3. 应用数据库迁移（必须执行到最新）
```bash
wrangler d1 migrations apply cfmail-db --remote
```

## 3. 设置 Worker Secrets

```bash
wrangler secret put RESEND_API_KEY
wrangler secret put RESEND_FROM
wrangler secret put JWT_SECRET
```

## 4. 配置收件路由（Email Routing）

1. 在 Cloudflare Dashboard 开启目标域 Email Routing。
2. 创建规则匹配 `*@mail.yourdomain.com`，Action 选 `Send to Worker`，绑定 Worker `cfmail`。

## 5. 本地开发

```bash
npm run dev
```

## 6. 部署

```bash
npm run deploy
```

## 7. API

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/mail/send`
- `GET /api/mail/inbox?folder=inbox|archive&state=all|unread|starred&q=&page=1&pageSize=20`
- `GET /api/mail/inbox/:id`
- `PATCH /api/mail/inbox/:id` (`isRead` / `isStarred` / `folder`)
- `GET /api/mail/sent?state=all|starred&q=&page=1&pageSize=20`
- `PATCH /api/mail/sent/:id` (`isStarred`)
- `GET /api/mail/drafts`
- `POST /api/mail/drafts` (新建或更新，含可选 `id`)
- `DELETE /api/mail/drafts/:id`
