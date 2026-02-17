const authCard = document.querySelector("#auth-card");
const appRoot = document.querySelector("#app");
const authForm = document.querySelector("#auth-form");
const tabs = document.querySelectorAll(".tab");
const userEmailEl = document.querySelector("#user-email");

const sendForm = document.querySelector("#send-form");
const saveDraftBtn = document.querySelector("#save-draft-btn");

const inboxList = document.querySelector("#inbox-list");
const sentList = document.querySelector("#sent-list");
const draftList = document.querySelector("#draft-list");
const detailEl = document.querySelector("#mail-detail");
const detailActions = document.querySelector("#detail-actions");

const inboxQ = document.querySelector("#inbox-q");
const inboxFolder = document.querySelector("#inbox-folder");
const inboxState = document.querySelector("#inbox-state");
const sentQ = document.querySelector("#sent-q");
const sentState = document.querySelector("#sent-state");

const refreshBtn = document.querySelector("#refresh-btn");
const refreshSentBtn = document.querySelector("#refresh-sent-btn");
const refreshDraftBtn = document.querySelector("#refresh-draft-btn");
const logoutBtn = document.querySelector("#logout-btn");
const toastEl = document.querySelector("#toast");

let mode = "login";
let toastTimer = null;
let currentDetail = null;
let currentDraftId = null;

const IS_FILE_PROTOCOL = window.location.protocol === "file:";

function showToast(message, isError = false) {
  toastEl.textContent = message;
  toastEl.classList.add("show");
  toastEl.classList.toggle("error", isError);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2200);
}

async function api(path, options = {}) {
  if (IS_FILE_PROTOCOL) throw new Error("请使用 wrangler dev 运行（file:// 无法调用 /api）");
  const res = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function setMode(nextMode) {
  mode = nextMode;
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.mode === nextMode));
}

function showAuth() {
  authCard.classList.remove("hidden");
  appRoot.classList.add("hidden");
}

function showApp(email) {
  userEmailEl.textContent = `当前登录: ${email}`;
  authCard.classList.add("hidden");
  appRoot.classList.remove("hidden");
}

function setDetail(kind, item, rawPreview = "") {
  currentDetail = { kind, item, rawPreview };
  if (kind === "inbox") {
    detailEl.textContent = [
      `ID: ${item.id}`,
      `From: ${item.sender}`,
      `To: ${item.recipient}`,
      `Subject: ${item.subject || "(No Subject)"}`,
      `Folder: ${item.folder}`,
      `Read: ${item.is_read ? "Yes" : "No"}`,
      `Starred: ${item.is_starred ? "Yes" : "No"}`,
      `Received: ${item.received_at}`,
      "",
      rawPreview || "(无原文)",
    ].join("\n");
  } else if (kind === "sent") {
    detailEl.textContent = [
      `ID: ${item.id}`,
      `From: ${item.sender}`,
      `To: ${item.to_list || "-"}`,
      `Cc: ${item.cc_list || "-"}`,
      `Bcc: ${item.bcc_list || "-"}`,
      `Subject: ${item.subject || "(No Subject)"}`,
      `Starred: ${item.is_starred ? "Yes" : "No"}`,
      `Sent: ${item.sent_at}`,
      `Provider Message ID: ${item.provider_id || "-"}`,
    ].join("\n");
  } else {
    detailEl.textContent = [
      `Draft ID: ${item.id}`,
      `To: ${item.to_list || "-"}`,
      `Cc: ${item.cc_list || "-"}`,
      `Bcc: ${item.bcc_list || "-"}`,
      `Subject: ${item.subject || "(No Subject)"}`,
      `Updated: ${item.updated_at}`,
      "",
      item.body_text || "",
    ].join("\n");
  }
  renderDetailActions();
}

function renderDetailActions() {
  detailActions.innerHTML = "";
  if (!currentDetail) return;

  if (currentDetail.kind === "inbox") {
    const item = currentDetail.item;
    const readBtn = document.createElement("button");
    readBtn.className = "ghost";
    readBtn.textContent = item.is_read ? "标为未读" : "标为已读";
    readBtn.onclick = async () => {
      await api(`/api/mail/inbox/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isRead: !item.is_read }),
      });
      showToast("状态已更新");
      await loadInbox();
    };

    const starBtn = document.createElement("button");
    starBtn.className = "ghost";
    starBtn.textContent = item.is_starred ? "取消星标" : "添加星标";
    starBtn.onclick = async () => {
      await api(`/api/mail/inbox/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isStarred: !item.is_starred }),
      });
      showToast("星标已更新");
      await loadInbox();
    };

    const folderBtn = document.createElement("button");
    folderBtn.className = "ghost";
    folderBtn.textContent = item.folder === "archive" ? "移回收件箱" : "归档";
    folderBtn.onclick = async () => {
      await api(`/api/mail/inbox/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ folder: item.folder === "archive" ? "inbox" : "archive" }),
      });
      showToast("文件夹已更新");
      await loadInbox();
    };

    detailActions.append(readBtn, starBtn, folderBtn);
  }

  if (currentDetail.kind === "sent") {
    const item = currentDetail.item;
    const starBtn = document.createElement("button");
    starBtn.className = "ghost";
    starBtn.textContent = item.is_starred ? "取消星标" : "添加星标";
    starBtn.onclick = async () => {
      await api(`/api/mail/sent/${item.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isStarred: !item.is_starred }),
      });
      showToast("星标已更新");
      await loadSent();
    };
    detailActions.append(starBtn);
  }

  if (currentDetail.kind === "draft") {
    const item = currentDetail.item;
    const loadBtn = document.createElement("button");
    loadBtn.className = "ghost";
    loadBtn.textContent = "载入编辑";
    loadBtn.onclick = () => loadDraftIntoCompose(item);

    const delBtn = document.createElement("button");
    delBtn.className = "ghost";
    delBtn.textContent = "删除草稿";
    delBtn.onclick = async () => {
      await api(`/api/mail/drafts/${item.id}`, { method: "DELETE", body: "{}" });
      if (currentDraftId === item.id) currentDraftId = null;
      showToast("草稿已删除");
      detailEl.textContent = "请先选择一封邮件";
      detailActions.innerHTML = "";
      await loadDrafts();
    };
    detailActions.append(loadBtn, delBtn);
  }
}

async function checkSession() {
  try {
    const data = await api("/api/auth/me", { method: "GET", headers: {} });
    showApp(data.user.email);
    await Promise.all([loadInbox(), loadSent(), loadDrafts()]);
  } catch {
    showAuth();
  }
}

function createInboxItem(item) {
  const btn = document.createElement("button");
  btn.className = `inbox-item ${item.is_read ? "read" : "unread"}`;
  const star = item.is_starred ? '<span class="star">★</span>' : '<span>☆</span>';
  btn.innerHTML = `<div class="item-top"><strong>${item.subject || "(No Subject)"}</strong>${star}</div><span>From: ${item.sender}</span><span>${item.received_at}</span>`;
  btn.addEventListener("click", async () => {
    const data = await api(`/api/mail/inbox/${item.id}`, { method: "GET" });
    setDetail("inbox", data.item, data.rawPreview);
    if (!item.is_read) {
      await api(`/api/mail/inbox/${item.id}`, { method: "PATCH", body: JSON.stringify({ isRead: true }) });
      await loadInbox();
    }
  });
  return btn;
}

async function loadInbox() {
  inboxList.innerHTML = "";
  try {
    const q = encodeURIComponent(inboxQ.value.trim());
    const folder = encodeURIComponent(inboxFolder.value);
    const state = encodeURIComponent(inboxState.value);
    const data = await api(`/api/mail/inbox?folder=${folder}&state=${state}&q=${q}&page=1&pageSize=20`, {
      method: "GET",
      headers: {},
    });
    if (!data.items?.length) {
      inboxList.innerHTML = "<p>暂无邮件</p>";
      return;
    }
    data.items.forEach((item) => inboxList.appendChild(createInboxItem(item)));
  } catch (err) {
    showToast(err.message, true);
  }
}

async function loadSent() {
  sentList.innerHTML = "";
  try {
    const q = encodeURIComponent(sentQ.value.trim());
    const state = encodeURIComponent(sentState.value);
    const data = await api(`/api/mail/sent?state=${state}&q=${q}&page=1&pageSize=20`, { method: "GET", headers: {} });
    if (!data.items?.length) {
      sentList.innerHTML = "<p>暂无记录</p>";
      return;
    }
    data.items.forEach((item) => {
      const btn = document.createElement("button");
      btn.className = "inbox-item";
      const star = item.is_starred ? '<span class="star">★</span>' : '<span>☆</span>';
      btn.innerHTML = `<div class="item-top"><strong>${item.subject || "(No Subject)"}</strong>${star}</div><span>To: ${item.to_list || "-"}</span><span>${item.sent_at}</span>`;
      btn.addEventListener("click", () => setDetail("sent", item));
      sentList.appendChild(btn);
    });
  } catch (err) {
    showToast(err.message, true);
  }
}

function loadDraftIntoCompose(draft) {
  sendForm.elements.to.value = draft.to_list || "";
  sendForm.elements.cc.value = draft.cc_list || "";
  sendForm.elements.bcc.value = draft.bcc_list || "";
  sendForm.elements.subject.value = draft.subject || "";
  sendForm.elements.text.value = draft.body_text || "";
  currentDraftId = draft.id;
  showToast("草稿已载入");
}

async function loadDrafts() {
  draftList.innerHTML = "";
  try {
    const data = await api("/api/mail/drafts", { method: "GET", headers: {} });
    if (!data.items?.length) {
      draftList.innerHTML = "<p>暂无草稿</p>";
      return;
    }
    data.items.forEach((item) => {
      const btn = document.createElement("button");
      btn.className = "inbox-item";
      btn.innerHTML = `<strong>${item.subject || "(无主题草稿)"}</strong><span>To: ${item.to_list || "-"}</span><span>${item.updated_at}</span>`;
      btn.addEventListener("click", () => setDetail("draft", item));
      draftList.appendChild(btn);
    });
  } catch (err) {
    showToast(err.message, true);
  }
}

tabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));

authForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(authForm);
  const payload = {
    email: String(formData.get("email") || "").trim(),
    password: String(formData.get("password") || ""),
  };
  try {
    const path = mode === "register" ? "/api/auth/register" : "/api/auth/login";
    const data = await api(path, { method: "POST", body: JSON.stringify(payload) });
    showToast(mode === "register" ? "注册成功" : "登录成功");
    showApp(data.user.email);
    await Promise.all([loadInbox(), loadSent(), loadDrafts()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

saveDraftBtn.addEventListener("click", async () => {
  const formData = new FormData(sendForm);
  const payload = {
    id: currentDraftId,
    to: String(formData.get("to") || "").trim(),
    cc: String(formData.get("cc") || "").trim(),
    bcc: String(formData.get("bcc") || "").trim(),
    subject: String(formData.get("subject") || "").trim(),
    text: String(formData.get("text") || ""),
  };
  try {
    const data = await api("/api/mail/drafts", { method: "POST", body: JSON.stringify(payload) });
    currentDraftId = data.id;
    showToast("草稿已保存");
    await loadDrafts();
  } catch (err) {
    showToast(err.message, true);
  }
});

sendForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(sendForm);
  const payload = {
    to: String(formData.get("to") || "").trim(),
    cc: String(formData.get("cc") || "").trim(),
    bcc: String(formData.get("bcc") || "").trim(),
    subject: String(formData.get("subject") || "").trim(),
    text: String(formData.get("text") || ""),
  };
  try {
    await api("/api/mail/send", { method: "POST", body: JSON.stringify(payload) });
    showToast("邮件发送成功");
    if (currentDraftId) {
      await api(`/api/mail/drafts/${currentDraftId}`, { method: "DELETE", body: "{}" });
      currentDraftId = null;
    }
    sendForm.reset();
    await Promise.all([loadSent(), loadDrafts()]);
  } catch (err) {
    showToast(err.message, true);
  }
});

inboxQ.addEventListener("change", loadInbox);
inboxFolder.addEventListener("change", loadInbox);
inboxState.addEventListener("change", loadInbox);
sentQ.addEventListener("change", loadSent);
sentState.addEventListener("change", loadSent);

refreshBtn.addEventListener("click", loadInbox);
refreshSentBtn.addEventListener("click", loadSent);
refreshDraftBtn.addEventListener("click", loadDrafts);

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
    showToast("已退出登录");
    showAuth();
  } catch (err) {
    showToast(err.message, true);
  }
});

checkSession();
if (IS_FILE_PROTOCOL) {
  showToast("当前是 file:// 预览，仅样式可看；功能请用 wrangler dev", true);
}
