// linux.sb daily check-in for Egern.
// v5 (2026-10-22):
//   1) 页面分类：已签到 / 签到页 / Cookie 过期 / Cloudflare 5xx / 人机验证 / 空响应
//   2) 遇到站点临时不可用（CF 502/521/522、挑战页、空响应）自动重试 3 次，间隔 8s
//   3) 失败通知带上真实原因和页面标题，不再一律报「CSRF Token 未找到」
const BASE = "https://linux.sb";
const CHECKIN_URL = `${BASE}/daily_checkin`;
const COOKIE_STORE = "linuxsb.cookie.v1";
const COOKIE_FP_STORE = "linuxsb.cookie.fp.v1";
const UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 8000;

function text(value) {
  if (typeof value === "string") return value;
  if (value == null) return "";
  try { return JSON.stringify(value); } catch (_) { return String(value); }
}

function sleep(ms) {
  return new Promise((resolve) => { try { setTimeout(resolve, ms); } catch (_) { resolve(); } });
}

function readHeader(headers, name) {
  if (!headers) return "";
  try {
    if (typeof headers.get === "function") return headers.get(name) || headers.get(name.toLowerCase()) || "";
  } catch (_) {}
  return headers[name] || headers[name.toLowerCase()] || "";
}

function readCookie(ctx) {
  return readHeader(ctx.request?.headers, "cookie").trim();
}

// env 检查宽容：只有明确 "false" 才禁用；{{{...}}} 字面量/空值按开启处理
function envEnabled(ctx, key) {
  const raw = String(ctx.env?.[key] ?? "");
  if (raw === "" || raw.includes("{{{")) return true;
  return raw === "true";
}

function getStoredCookie(ctx) {
  try { return String(ctx.storage.get(COOKIE_STORE) || "").trim(); } catch (_) { return ""; }
}

function setStoredCookie(ctx, cookie) {
  try { ctx.storage.set(COOKIE_STORE, cookie); } catch (_) {}
}

function fingerprint(cookie) {
  let h = 2166136261;
  for (let i = 0; i < cookie.length; i += 1) {
    h ^= cookie.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

async function notify(ctx, title, body) {
  if (typeof ctx.notify === "function") await ctx.notify({ title, body });
}

function translateHttpError(error) {
  const raw = String(error?.message || error || "");
  if (/JSON Parse|Unable to parse JSON|Unexpected identifier|Unexpected token|SyntaxError/i.test(raw)) {
    return new Error("接口返回了非 JSON 内容（可能是 HTML 页面）");
  }
  return error instanceof Error ? error : new Error(raw);
}

function readStatus(response) {
  const raw = response?.status ?? response?.statusCode ?? response?.code ?? 0;
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

// Egern 的 ctx.http 会强解析 JSON，非 JSON 内容抛错，整段包住并尽量拿回 body
async function httpGet(ctx, url, headers) {
  try {
    const response = await ctx.http.get(url, { timeout: 20000, headers });
    let body = "";
    if (response && typeof response.text === "function") {
      try { const raw = await response.text(); if (typeof raw === "string") body = raw; } catch (_) {}
    }
    if (!body) body = text(response?.body ?? response?.data ?? response);
    return { status: readStatus(response), body: body || "" };
  } catch (error) {
    const err = translateHttpError(error);
    return { status: 0, body: "", error: err.message };
  }
}

async function httpPost(ctx, url, headers, body) {
  try {
    const response = await ctx.http.post(url, { timeout: 20000, headers, body });
    let textBody = "";
    if (response && typeof response.text === "function") {
      try { const raw = await response.text(); if (typeof raw === "string") textBody = raw; } catch (_) {}
    }
    if (!textBody) textBody = text(response?.body ?? response?.data ?? response);
    return { status: readStatus(response), body: textBody || "" };
  } catch (error) {
    const err = translateHttpError(error);
    return { status: 0, body: "", error: err.message };
  }
}

function pageTitle(html) {
  const m = String(html || "").match(/<title[^>]*>([^<]{0,80})<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim() : "";
}

// 页面类型判定
function classify(html) {
  const t = String(html || "");
  if (!t.trim()) return "empty";
  if (/已签到|已连续签到|今日已签到|今天已签到/.test(t)) return "signed";
  if (/cf-error-details|Attention Required|Sorry, you have been blocked|Origin (?:unavailable|DNS)|Web server is down|Error 52[0-9]|Error 50[234]/i.test(t)) return "unavailable";
  if (/name=["']?password["']?/i.test(t) || /<title>[^<]*登录/i.test(t)) return "login";
  if (/人机验证|turnstile|cf-turnstile|night-guard|请稍候/i.test(t)) return "captcha";
  if (/Just a moment|challenge-platform|cf-challenge|cf-browser-verification|Checking your browser/i.test(t)) return "challenge";
  if (/_csrf/.test(t)) return "checkin";
  return "unknown";
}

function extractCsrf(html) {
  const patterns = [
    /name=["']_csrf["'][^>]*value=["']([^"']+)["']/i,
    /value=["']([^"']+)["'][^>]*name=["']_csrf["']/i,
    /name=["']csrf-token["'][^>]*content=["']([^"']+)["']/i,
    /content=["']([^"']+)["'][^>]*name=["']csrf-token["']/i
  ];
  for (let i = 0; i < patterns.length; i += 1) {
    const m = html.match(patterns[i]);
    if (m && m[1]) return m[1];
  }
  return "";
}

async function capture(ctx) {
  if (!envEnabled(ctx, "CaptureCookie")) {
    return { ok: true, disabled: true };
  }
  const cookie = readCookie(ctx);
  if (!cookie) return { ok: false, ignored: true };
  const fp = fingerprint(cookie);
  let old = "";
  try { old = String(ctx.storage.get(COOKIE_FP_STORE) || ""); } catch (_) {}
  setStoredCookie(ctx, cookie);
  try { ctx.storage.set(COOKIE_FP_STORE, fp); } catch (_) {}
  if (fp !== old) await notify(ctx, "linux.sb", "已获取 Cookie，自动签到已就绪");
  return { ok: true, changed: fp !== old };
}

function reasonOf(kind, status, title) {
  if (kind === "empty") return `站点无响应（空返回${status ? ` HTTP ${status}` : ""}）`;
  if (kind === "unavailable") return `站点临时不可用（Cloudflare ${status || "5xx"}），重试后仍失败`;
  if (kind === "challenge") return "站点正在 Cloudflare 验证，重试后仍被拦";
  if (kind === "captcha") return "站点要求人机验证，请在浏览器打开 linux.sb 完成一次";
  if (title) return `未识别的页面（${title}），页面结构可能已变化`;
  return "未识别的页面，页面结构可能已变化";
}

async function checkin(ctx) {
  const cookie = getStoredCookie(ctx);
  if (!cookie) {
    await notify(ctx, "linux.sb 签到失败", "还没有获取到 Cookie，请打开 linux.sb 并登录");
    return { ok: false, error: "cookie_not_captured" };
  }
  const headers = {
    Cookie: cookie,
    "User-Agent": UA,
    Accept: "text/html,application/xhtml+xml",
    "Accept-Language": "zh-CN,zh;q=0.9"
  };

  let last = { kind: "empty", status: 0, title: "" };
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    const res = await httpGet(ctx, CHECKIN_URL, headers);
    const kind = classify(res.body);
    last = { kind, status: res.status, title: pageTitle(res.body) };

    if (kind === "signed") {
      await notify(ctx, "linux.sb 签到", "今天已经签到");
      return { ok: true, status: "already-signed-in" };
    }
    if (kind === "login") {
      await notify(ctx, "linux.sb Cookie 过期", "登录态已失效，请打开 linux.sb 重新登录一次");
      return { ok: false, error: "cookie_expired" };
    }
    if (kind === "checkin") {
      const csrf = extractCsrf(res.body);
      if (!csrf) {
        await notify(ctx, "linux.sb 签到失败", "签到页没有 CSRF Token，页面结构可能已变化");
        return { ok: false, error: "csrf_not_found" };
      }
      await httpPost(ctx, CHECKIN_URL, {
        ...headers,
        "Content-Type": "application/x-www-form-urlencoded",
        Referer: CHECKIN_URL
      }, `_csrf=${encodeURIComponent(csrf)}`);
      const after = await httpGet(ctx, CHECKIN_URL, headers);
      const ok = /已签到|已连续签到|今日已签到|今天已签到/.test(after.body);
      await notify(ctx, "linux.sb 签到", ok ? "签到成功" : "未确认签到结果，请打开 linux.sb 核对");
      return { ok, status: ok ? "signed-in" : "unconfirmed" };
    }
    // empty / unavailable / challenge / captcha / unknown → 可重试
    if (attempt < MAX_ATTEMPTS) await sleep(RETRY_DELAY_MS);
  }

  const reason = reasonOf(last.kind, last.status, last.title);
  await notify(ctx, "linux.sb 签到失败", reason);
  return { ok: false, error: last.kind, status: last.status, title: last.title };
}

export default async function (ctx) {
  if (ctx.request) return capture(ctx);
  return checkin(ctx);
}
