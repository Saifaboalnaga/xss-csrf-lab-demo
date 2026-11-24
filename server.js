/*
 * XSS + CSRF Educational Lab (demo)
 * ---------------------------------
 * INTENTIONALLY VULNERABLE. Run only on your own machine (bound to 127.0.0.1).
 *
 * Two apps:
 *   - Vulnerable bank app  -> http://localhost:3000
 *   - "Attacker" site       -> http://localhost:4000 (a different origin, for the CSRF demo)
 *
 * Security levels (switch from the top bar):
 *   0 = Vulnerable   : no output encoding, no CSRF token, lax cookie
 *   1 = CSRF token   : CSRF token required, but XSS still present  -> shows XSS defeating CSRF
 *   2 = Secure       : output encoding + CSP + CSRF token + SameSite=Strict cookie
 */
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");

const HOST = process.env.BIND_HOST || "127.0.0.1";
const APP_PORT = Number(process.env.APP_PORT || 3000);
const ATTACKER_PORT = Number(process.env.ATTACKER_PORT || 4000);

const LEVELS = { 0: "Vulnerable", 1: "CSRF token only", 2: "Secure" };
let level = 0;

// In-memory demo data (resets on restart)
const user = { name: "Alice", email: "alice@bank.test", balance: 1200 };
let comments = [{ author: "Bob", text: "Great service, fast transfers!" }];
const csrfTokens = new Map(); // session -> token
const SESSION = "alice-session-demo";

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function render(content, title) {
  const out = level === 2 ? escapeHtml : (s) => s; // the core XSS fix
  const tok = csrfTokens.get(SESSION) || "";
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title} · SafeBank Lab</title>
<link rel="stylesheet" href="/style.css"></head><body>
<div class="bar"><b>🏦 SafeBank <small>(lab)</small></b>
<form method="post" action="/level" class="lv">Security level:
${Object.entries(LEVELS).map(([k, v]) => `<button name="level" value="${k}" class="${+k === level ? "on" : ""}">${k} · ${v}</button>`).join("")}
</form></div>
<main>${content({ out, tok })}</main>
<footer>Educational lab — intentionally vulnerable, local use only.</footer></body></html>`;
}

/* ------------------------- vulnerable bank app ------------------------- */
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// "Log in" Alice automatically and set the session cookie according to the level
app.use((req, res, next) => {
  if (!csrfTokens.has(SESSION)) csrfTokens.set(SESSION, crypto.randomBytes(16).toString("hex"));
  res.cookie("session", SESSION, { httpOnly: true, sameSite: level === 2 ? "strict" : "lax" });
  if (level === 2) res.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'");
  next();
});

function checkCsrf(req, res) {
  // Alice must be logged in (the browser sends her cookie automatically, which is exactly why CSRF works)
  if (req.cookies.session !== SESSION) { res.status(401).send("Not logged in"); return false; }
  if (level === 0) return true; // vulnerable: no token check
  const sent = req.body._csrf || req.get("X-CSRF-Token");
  if (sent && sent === csrfTokens.get(SESSION)) return true;
  res.status(403).send(render(() => `<div class="card bad"><h2>403 — CSRF token missing or invalid</h2>
  <p>The request was blocked because it did not include the secret token that only the real page knows.</p>
  <a href="/">Back</a></div>`, "Blocked"));
  return false;
}

app.post("/level", (req, res) => {
  level = [0, 1, 2].includes(+req.body.level) ? +req.body.level : 0;
  res.redirect(req.get("Referer") || "/");
});

app.get("/", (req, res) => res.send(render(({ out, tok }) => `
<div class="card"><h2>Welcome, ${out(user.name)}</h2>
<p>Email on file: <b id="email">${out(user.email)}</b> · Balance: <b>$${user.balance}</b></p>
<form method="post" action="/change-email" class="row">
  ${level > 0 ? `<input type="hidden" name="_csrf" value="${tok}">` : ""}
  <input name="email" placeholder="new email"><button>Change email</button>
</form></div>

<div class="card"><h2>Lab 1 · Reflected XSS</h2>
<form action="/search" class="row"><input name="q" placeholder="search transactions"><button>Search</button></form></div>

<div class="card"><h2>Lab 2 · Stored XSS — customer reviews</h2>
${comments.map(c => `<div class="comment"><b>${out(c.author)}</b><p>${out(c.text)}</p></div>`).join("")}
<form method="post" action="/comment" class="col">
  ${level > 0 ? `<input type="hidden" name="_csrf" value="${tok}">` : ""}
  <input name="author" placeholder="your name"><textarea name="text" rows="2" placeholder="write a review"></textarea>
  <button>Post review</button></form>
<form method="post" action="/reset"><button class="link">Reset lab data</button></form></div>

<div class="card"><h2>Lab 3 · CSRF</h2>
<p>Open the attacker site in this browser: <a href="http://localhost:${ATTACKER_PORT}" target="_blank">http://localhost:${ATTACKER_PORT}</a>,
then come back and check Alice's email above.</p></div>`, "Home")));

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(render(({ out }) => `<div class="card"><h2>Search results</h2>
  <p>No transactions found for: <b>${out(q)}</b></p><a href="/">Back</a></div>`, "Search"));
});

app.post("/comment", (req, res) => {
  if (!checkCsrf(req, res)) return;
  comments.push({ author: req.body.author || "Anonymous", text: req.body.text || "" });
  res.redirect("/");
});

app.post("/change-email", (req, res) => {
  if (!checkCsrf(req, res)) return;
  user.email = req.body.email || user.email;
  if (req.get("X-Requested-With") === "fetch") return res.json({ ok: true, email: user.email });
  res.redirect("/");
});

app.post("/reset", (req, res) => {
  user.email = "alice@bank.test";
  comments = [{ author: "Bob", text: "Great service, fast transfers!" }];
  res.redirect("/");
});

app.listen(APP_PORT, HOST, () => console.log(`SafeBank lab on http://localhost:${APP_PORT}`));

/* ----------------------------- attacker site ----------------------------- */
const attacker = express();
attacker.get("/", (req, res) => res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Free Gift!</title>
<style>body{font-family:system-ui;text-align:center;padding:60px;background:#fff7e6}</style></head><body>
<h1>🎁 You won a free gift card!</h1><p>Loading your prize...</p>
<!-- Hidden auto-submitting form: the browser attaches Alice's SafeBank cookie (CSRF) -->
<form id="f" method="post" action="http://localhost:${APP_PORT}/change-email" target="sink">
  <input type="hidden" name="email" value="attacker@evil.test"></form>
<iframe name="sink" style="display:none"></iframe>
<script>document.getElementById('f').submit()</script>
<p><small>(Lab: this page silently sent a request to SafeBank. Go back and refresh.)</small></p>
</body></html>`));
attacker.listen(ATTACKER_PORT, HOST, () => console.log(`Attacker site on http://localhost:${ATTACKER_PORT}`));
