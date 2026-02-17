export interface Env {
  CFMAILDB: D1Database;
  MAIL_RAW: R2Bucket;
  ASSETS: Fetcher;
  APP_NAME: string;
  RESEND_API_KEY: string;
  RESEND_FROM: string;
  JWT_SECRET: string;
}

type SessionPayload = {
  uid: number;
  email: string;
  exp: number;
};

type EmailMessage = {
  from: string;
  to: string;
  headers: Headers;
  raw: ReadableStream;
  setReject: (reason: string) => void;
};

const COOKIE_NAME = "cfmail_session";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;

function json(data: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

function badRequest(message: string) {
  return json({ error: message }, { status: 400 });
}

function unauthorized(message = "Unauthorized") {
  return json({ error: message }, { status: 401 });
}

function misconfigured(missing: string[]) {
  return json(
    {
      error: "Server configuration missing",
      missing,
    },
    { status: 500 },
  );
}

function getMissingCoreConfig(env: Env): string[] {
  const missing: string[] = [];
  const db = (env as Partial<Env>).CFMAILDB as unknown;
  const hasD1Binding = !!db && typeof db === "object" && typeof (db as { prepare?: unknown }).prepare === "function";
  if (!hasD1Binding) missing.push("CFMAILDB D1 binding");

  if (!(env as Partial<Env>).JWT_SECRET) missing.push("JWT_SECRET secret");
  return missing;
}

function getMissingSendConfig(env: Env): string[] {
  const missing: string[] = [];
  if (!(env as Partial<Env>).RESEND_API_KEY) missing.push("RESEND_API_KEY secret");
  if (!(env as Partial<Env>).RESEND_FROM) missing.push("RESEND_FROM secret");
  return missing;
}

function hasR2Binding(env: Env): boolean {
  const bucket = (env as Partial<Env>).MAIL_RAW as unknown;
  return !!bucket && typeof bucket === "object" && typeof (bucket as { get?: unknown }).get === "function";
}

function parseCookie(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {};
  const out: Record<string, string> = {};
  for (const item of cookieHeader.split(";")) {
    const idx = item.indexOf("=");
    if (idx < 0) continue;
    const key = item.slice(0, idx).trim();
    const value = item.slice(idx + 1).trim();
    out[key] = decodeURIComponent(value);
  }
  return out;
}

function base64url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const bin = atob(normalized + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function importHmacKey(secret: string) {
  const secretBytes = new TextEncoder().encode(secret);
  const secretBuffer = secretBytes.buffer as ArrayBuffer;
  return crypto.subtle.importKey(
    "raw",
    secretBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signToken(payload: SessionPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64url(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await importHmacKey(secret);
  const dataBytes = new TextEncoder().encode(data);
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes.buffer as ArrayBuffer);
  return `${data}.${base64url(new Uint8Array(sig))}`;
}

async function verifyToken(token: string, secret: string): Promise<SessionPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, sig] = parts;
  const data = `${header}.${payload}`;
  const key = await importHmacKey(secret);
  const dataBytes = new TextEncoder().encode(data);
  const sigBytes = fromBase64url(sig);
  const ok = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes.buffer as ArrayBuffer,
    dataBytes.buffer as ArrayBuffer,
  );
  if (!ok) return null;
  let parsed: SessionPayload;
  try {
    parsed = JSON.parse(new TextDecoder().decode(fromBase64url(payload)));
  } catch {
    return null;
  }
  if (!parsed?.uid || !parsed?.email || !parsed?.exp) return null;
  if (Date.now() >= parsed.exp * 1000) return null;
  return parsed;
}

function buildSessionCookie(token: string) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${TOKEN_TTL_SECONDS}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function hashPassword(password: string, saltBytes?: Uint8Array): Promise<{ hash: string; salt: string }> {
  const salt = saltBytes ?? crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  return {
    hash: base64url(new Uint8Array(bits)),
    salt: base64url(salt),
  };
}

async function verifyPassword(password: string, salt: string, expectedHash: string): Promise<boolean> {
  const saltBytes = fromBase64url(salt);
  const { hash } = await hashPassword(password, saltBytes);
  return hash === expectedHash;
}

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseAddressList(input?: string): string[] {
  if (!input) return [];
  return input
    .split(/[;,]/)
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

async function requireAuth(request: Request, env: Env): Promise<SessionPayload | null> {
  const cookies = parseCookie(request.headers.get("cookie"));
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

async function readJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

async function handleRegister(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ email?: string; password?: string }>(request);
  if (!body?.email || !body?.password) return badRequest("email and password are required");
  const email = body.email.trim().toLowerCase();
  const password = body.password;
  if (!isValidEmail(email)) return badRequest("invalid email");
  if (password.length < 8) return badRequest("password must be at least 8 characters");

  const existed = await env.CFMAILDB.prepare("SELECT id FROM users WHERE email = ?1").bind(email).first<{ id: number }>();
  if (existed) return json({ error: "email already registered" }, { status: 409 });

  const { hash, salt } = await hashPassword(password);
  const result = await env.CFMAILDB.prepare(
    "INSERT INTO users (email, password_hash, salt) VALUES (?1, ?2, ?3)",
  )
    .bind(email, hash, salt)
    .run();

  const uid = Number(result.meta.last_row_id);
  const token = await signToken(
    { uid, email, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS },
    env.JWT_SECRET,
  );

  return json(
    { user: { id: uid, email } },
    {
      headers: {
        "set-cookie": buildSessionCookie(token),
      },
    },
  );
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ email?: string; password?: string }>(request);
  if (!body?.email || !body?.password) return badRequest("email and password are required");
  const email = body.email.trim().toLowerCase();
  const user = await env.CFMAILDB.prepare("SELECT id, email, password_hash, salt FROM users WHERE email = ?1")
    .bind(email)
    .first<{ id: number; email: string; password_hash: string; salt: string }>();

  if (!user) return unauthorized("invalid credentials");
  const passOk = await verifyPassword(body.password, user.salt, user.password_hash);
  if (!passOk) return unauthorized("invalid credentials");

  const token = await signToken(
    { uid: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS },
    env.JWT_SECRET,
  );

  return json(
    { user: { id: user.id, email: user.email } },
    {
      headers: {
        "set-cookie": buildSessionCookie(token),
      },
    },
  );
}

async function handleSendMail(request: Request, env: Env): Promise<Response> {
  const missingSend = getMissingSendConfig(env);
  if (missingSend.length) return misconfigured(missingSend);

  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const body = await readJson<{
    to?: string;
    cc?: string;
    bcc?: string;
    subject?: string;
    text?: string;
    html?: string;
  }>(request);
  if (!body?.to || !body?.subject || !body?.text) {
    return badRequest("to, subject, text are required");
  }
  const to = parseAddressList(body.to);
  const cc = parseAddressList(body.cc);
  const bcc = parseAddressList(body.bcc);
  if (!to.length) return badRequest("at least one recipient is required");
  const recipients = [...to, ...cc, ...bcc];
  if (recipients.some((email) => !isValidEmail(email))) {
    return badRequest("invalid email address in recipients");
  }

  const payload = {
    from: env.RESEND_FROM,
    to,
    cc: cc.length ? cc : undefined,
    bcc: bcc.length ? bcc : undefined,
    subject: body.subject.trim(),
    text: body.text,
    html: body.html,
    reply_to: session.email,
  };

  const rs = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await rs.json<unknown>();
  if (!rs.ok) {
    return json({ error: "resend failed", details: data }, { status: 502 });
  }

  const provider = (data || {}) as { id?: string };
  await env.CFMAILDB.prepare(
    `INSERT INTO sent_emails (user_id, sender, to_list, cc_list, bcc_list, subject, body_text, provider_id)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
  )
    .bind(
      session.uid,
      env.RESEND_FROM,
      to.join(", "),
      cc.join(", "),
      bcc.join(", "),
      body.subject.trim(),
      body.text,
      provider.id || null,
    )
    .run();

  return json({ ok: true, provider: data });
}

function parsePage(url: URL) {
  const page = Math.max(1, Number(url.searchParams.get("page") || "1") || 1);
  const pageSizeRaw = Number(url.searchParams.get("pageSize") || "20") || 20;
  const pageSize = Math.min(50, Math.max(1, pageSizeRaw));
  const offset = (page - 1) * pageSize;
  return { page, pageSize, offset };
}

async function handleInbox(request: Request, env: Env): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const url = new URL(request.url);
  const folder = url.searchParams.get("folder") === "archive" ? "archive" : "inbox";
  const state = url.searchParams.get("state") || "all";
  const q = (url.searchParams.get("q") || "").trim();
  const { page, pageSize, offset } = parsePage(url);

  let where = "recipient = ? AND folder = ?";
  const binds: (string | number)[] = [session.email, folder];
  if (state === "unread") where += " AND is_read = 0";
  if (state === "starred") where += " AND is_starred = 1";
  if (q) {
    where += " AND (subject LIKE ? OR sender LIKE ? OR snippet LIKE ?)";
    const like = `%${q}%`;
    binds.push(like, like, like);
  }

  const rows = await env.CFMAILDB.prepare(
    `SELECT id, recipient, sender, subject, snippet, size_bytes, is_read, is_starred, folder, received_at
     FROM inbound_emails
     WHERE ${where}
     ORDER BY received_at DESC
     LIMIT ? OFFSET ?`,
  )
    .bind(...binds, pageSize, offset)
    .all<{
      id: number;
      recipient: string;
      sender: string;
      subject: string;
      snippet: string;
      size_bytes: number;
      is_read: number;
      is_starred: number;
      folder: string;
      received_at: string;
    }>();

  const total = await env.CFMAILDB.prepare(`SELECT COUNT(*) AS count FROM inbound_emails WHERE ${where}`)
    .bind(...binds)
    .first<{ count: number }>();

  return json({ items: rows.results || [], page, pageSize, total: total?.count || 0, folder, state, q });
}

async function handleInboxDetail(request: Request, env: Env, id: number): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const row = await env.CFMAILDB.prepare(
    `SELECT id, recipient, sender, subject, snippet, raw_key, size_bytes, is_read, is_starred, folder, received_at
     FROM inbound_emails WHERE id = ?1`,
  )
    .bind(id)
    .first<{
      id: number;
      recipient: string;
      sender: string;
      subject: string;
      snippet: string;
      raw_key: string | null;
      size_bytes: number | null;
      is_read: number;
      is_starred: number;
      folder: string;
      received_at: string;
    }>();

  if (!row) return json({ error: "not found" }, { status: 404 });
  if (row.recipient !== session.email) return unauthorized();

  let rawPreview = "";
  if (row.raw_key) {
    const obj = await env.MAIL_RAW.get(row.raw_key);
    if (obj) {
      const rawText = await obj.text();
      rawPreview = rawText.slice(0, 20000);
    }
  }

  return json({ item: row, rawPreview });
}

async function handleInboxPatch(request: Request, env: Env, id: number): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const row = await env.CFMAILDB.prepare("SELECT id, recipient FROM inbound_emails WHERE id = ?1")
    .bind(id)
    .first<{ id: number; recipient: string }>();
  if (!row) return json({ error: "not found" }, { status: 404 });
  if (row.recipient !== session.email) return unauthorized();

  const body = await readJson<{ isRead?: boolean; isStarred?: boolean; folder?: "inbox" | "archive" }>(request);
  if (!body) return badRequest("invalid payload");

  const sets: string[] = [];
  const binds: (number | string)[] = [];
  if (typeof body.isRead === "boolean") {
    sets.push("is_read = ?");
    binds.push(body.isRead ? 1 : 0);
  }
  if (typeof body.isStarred === "boolean") {
    sets.push("is_starred = ?");
    binds.push(body.isStarred ? 1 : 0);
  }
  if (body.folder) {
    if (body.folder !== "inbox" && body.folder !== "archive") return badRequest("invalid folder");
    sets.push("folder = ?");
    binds.push(body.folder);
  }
  if (!sets.length) return badRequest("nothing to update");

  await env.CFMAILDB.prepare(`UPDATE inbound_emails SET ${sets.join(", ")} WHERE id = ?`)
    .bind(...binds, id)
    .run();
  return json({ ok: true });
}

async function handleSent(request: Request, env: Env): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const url = new URL(request.url);
  const q = (url.searchParams.get("q") || "").trim();
  const state = url.searchParams.get("state") || "all";
  const { page, pageSize, offset } = parsePage(url);

  let where = "user_id = ?";
  const binds: (string | number)[] = [session.uid];
  if (state === "starred") where += " AND is_starred = 1";
  if (q) {
    where += " AND (subject LIKE ? OR to_list LIKE ? OR cc_list LIKE ?)";
    const like = `%${q}%`;
    binds.push(like, like, like);
  }

  const rows = await env.CFMAILDB.prepare(
    `SELECT id, sender, to_list, cc_list, bcc_list, subject, sent_at, provider_id, is_starred
     FROM sent_emails
     WHERE ${where}
     ORDER BY sent_at DESC
     LIMIT ? OFFSET ?`,
  )
    .bind(...binds, pageSize, offset)
    .all<{
      id: number;
      sender: string;
      to_list: string;
      cc_list: string;
      bcc_list: string;
      subject: string;
      sent_at: string;
      provider_id: string | null;
      is_starred: number;
    }>();

  const total = await env.CFMAILDB.prepare(`SELECT COUNT(*) AS count FROM sent_emails WHERE ${where}`)
    .bind(...binds)
    .first<{ count: number }>();
  return json({ items: rows.results || [], page, pageSize, total: total?.count || 0, state, q });
}

async function handleSentPatch(request: Request, env: Env, id: number): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();
  const body = await readJson<{ isStarred?: boolean }>(request);
  if (!body || typeof body.isStarred !== "boolean") return badRequest("isStarred is required");

  const result = await env.CFMAILDB.prepare(
    "UPDATE sent_emails SET is_starred = ?1 WHERE id = ?2 AND user_id = ?3",
  )
    .bind(body.isStarred ? 1 : 0, id, session.uid)
    .run();
  if (!result.success) return json({ error: "update failed" }, { status: 500 });
  return json({ ok: true });
}

async function handleDrafts(request: Request, env: Env): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();

  const rows = await env.CFMAILDB.prepare(
    `SELECT id, to_list, cc_list, bcc_list, subject, body_text, created_at, updated_at
     FROM drafts
     WHERE user_id = ?1
     ORDER BY updated_at DESC
     LIMIT 50`,
  )
    .bind(session.uid)
    .all<{
      id: number;
      to_list: string;
      cc_list: string;
      bcc_list: string;
      subject: string;
      body_text: string;
      created_at: string;
      updated_at: string;
    }>();
  return json({ items: rows.results || [] });
}

async function handleSaveDraft(request: Request, env: Env): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();
  const body = await readJson<{
    id?: number;
    to?: string;
    cc?: string;
    bcc?: string;
    subject?: string;
    text?: string;
  }>(request);
  if (!body) return badRequest("invalid payload");

  const to = body.to?.trim() || "";
  const cc = body.cc?.trim() || "";
  const bcc = body.bcc?.trim() || "";
  const subject = body.subject?.trim() || "";
  const text = body.text || "";

  if (body.id) {
    await env.CFMAILDB.prepare(
      `UPDATE drafts
       SET to_list = ?1, cc_list = ?2, bcc_list = ?3, subject = ?4, body_text = ?5, updated_at = datetime('now')
       WHERE id = ?6 AND user_id = ?7`,
    )
      .bind(to, cc, bcc, subject, text, body.id, session.uid)
      .run();
    return json({ ok: true, id: body.id });
  }

  const created = await env.CFMAILDB.prepare(
    `INSERT INTO drafts (user_id, to_list, cc_list, bcc_list, subject, body_text)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(session.uid, to, cc, bcc, subject, text)
    .run();
  return json({ ok: true, id: Number(created.meta.last_row_id) });
}

async function handleDeleteDraft(request: Request, env: Env, id: number): Promise<Response> {
  const session = await requireAuth(request, env);
  if (!session) return unauthorized();
  await env.CFMAILDB.prepare("DELETE FROM drafts WHERE id = ?1 AND user_id = ?2").bind(id, session.uid).run();
  return json({ ok: true });
}

async function routeApi(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/api/")) {
    const missingCore = getMissingCoreConfig(env);
    if (missingCore.length) return misconfigured(missingCore);
  }

  if (url.pathname === "/api/health") {
    return json({ ok: true, app: env.APP_NAME, now: new Date().toISOString() });
  }

  if (url.pathname === "/api/auth/register" && request.method === "POST") {
    return handleRegister(request, env);
  }

  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    return handleLogin(request, env);
  }

  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    return json(
      { ok: true },
      {
        headers: {
          "set-cookie": clearSessionCookie(),
        },
      },
    );
  }

  if (url.pathname === "/api/auth/me" && request.method === "GET") {
    const session = await requireAuth(request, env);
    if (!session) return unauthorized();
    return json({ user: { id: session.uid, email: session.email } });
  }

  if (url.pathname === "/api/mail/send" && request.method === "POST") {
    return handleSendMail(request, env);
  }

  if (url.pathname === "/api/mail/inbox" && request.method === "GET") {
    return handleInbox(request, env);
  }

  if (url.pathname === "/api/mail/sent" && request.method === "GET") {
    return handleSent(request, env);
  }

  if (url.pathname === "/api/mail/drafts" && request.method === "GET") {
    return handleDrafts(request, env);
  }
  if (url.pathname === "/api/mail/drafts" && request.method === "POST") {
    return handleSaveDraft(request, env);
  }

  const detailMatch = url.pathname.match(/^\/api\/mail\/inbox\/(\d+)$/);
  if (detailMatch && request.method === "GET") {
    return handleInboxDetail(request, env, Number(detailMatch[1]));
  }

  if (detailMatch && request.method === "PATCH") {
    return handleInboxPatch(request, env, Number(detailMatch[1]));
  }

  const sentMatch = url.pathname.match(/^\/api\/mail\/sent\/(\d+)$/);
  if (sentMatch && request.method === "PATCH") {
    return handleSentPatch(request, env, Number(sentMatch[1]));
  }

  const draftMatch = url.pathname.match(/^\/api\/mail\/drafts\/(\d+)$/);
  if (draftMatch && request.method === "DELETE") {
    return handleDeleteDraft(request, env, Number(draftMatch[1]));
  }

  return null;
}

async function handleInboundEmail(message: EmailMessage, env: Env): Promise<void> {
  try {
    if (!hasR2Binding(env)) {
      message.setReject("MAIL_RAW R2 binding is missing");
      return;
    }

    const subject = message.headers.get("subject") || "(No Subject)";
    const rawBuffer = await new Response(message.raw).arrayBuffer();
    const rawKey = `inbound/${Date.now()}-${crypto.randomUUID()}.eml`;

    await env.MAIL_RAW.put(rawKey, rawBuffer, {
      httpMetadata: { contentType: "message/rfc822" },
    });

    await env.CFMAILDB.prepare(
      `INSERT INTO inbound_emails (recipient, sender, subject, snippet, raw_key, size_bytes)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
    )
      .bind(
        message.to.trim().toLowerCase(),
        message.from.trim().toLowerCase(),
        subject,
        subject.slice(0, 140),
        rawKey,
        rawBuffer.byteLength,
      )
      .run();
  } catch (err) {
    const reason = err instanceof Error ? err.message : "inbound processing failed";
    message.setReject(reason);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const apiResp = await routeApi(request, env);
    if (apiResp) return apiResp;
    return env.ASSETS.fetch(request);
  },

  async email(message: EmailMessage, env: Env): Promise<void> {
    await handleInboundEmail(message, env);
  },
};
