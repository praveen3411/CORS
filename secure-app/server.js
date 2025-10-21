// server.js — Secure CSRF-protected profile update demo
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const PROD = process.env.NODE_ENV === "production";

app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());

// Session cookie: SameSite=Lax blocks most CSRF; secure only in prod (HTTPS)
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: PROD, // set true only behind HTTPS in prod
      sameSite: "lax", // blocks most cross-site requests from sending cookies
      maxAge: 1000 * 60 * 60,
    },
  })
);

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// ---- Auth (DEMO) ----
app.post("/login", (req, res) => {
  // Pretend the user authenticated successfully
  req.session.userId = "123";
  req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  res.json({ ok: true, message: "Logged in for demo." });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/csrf-token", (req, res) => {
  if (!req.session.userId)
    return res.status(401).json({ error: "Unauthenticated" });
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
  }
  res.json({ csrfToken: req.session.csrfToken });
});

// ---- Middleware ----
function requireAuth(req, res, next) {
  if (!req.session.userId)
    return res.status(401).json({ error: "Unauthenticated" });
  next();
}

function requireSameOrigin(req, res, next) {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (origin && origin !== ORIGIN) {
    return res
      .status(403)
      .json({ error: "Bad origin", got: origin, want: ORIGIN });
  }
  const referer = req.headers.referer;
  if (!origin && referer && !referer.startsWith(ORIGIN)) {
    return res.status(403).json({ error: "Bad referer", got: referer });
  }
  next();
}

function requireJsonAndAjaxHeaders(req, res, next) {
  if (!req.is("application/json")) {
    return res
      .status(415)
      .json({ error: "Content-Type must be application/json" });
  }
  const xhr = req.get("X-Requested-With");
  if (xhr !== "XMLHttpRequest") {
    return res
      .status(400)
      .json({ error: "Missing or invalid X-Requested-With header" });
  }
  next();
}

function verifyCsrf(req, res, next) {
  const token = req.get("X-CSRF-Token");
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  next();
}

function requirePasswordWhenChangingEmail(req, res, next) {
  const changingEmail = typeof req.body?.email === "string";
  if (!changingEmail) return next();
  const suppliedPassword = req.body?.currentPassword;
  // DEMO ONLY: accept 'demo-password'
  if (suppliedPassword !== "demo-password") {
    return res
      .status(401)
      .json({ error: "Re-authentication required to change email" });
  }
  next();
}

// ---- Protected endpoint ----
app.post(
  "/api/profile/update",
  requireAuth,
  requireSameOrigin,
  requireJsonAndAjaxHeaders,
  verifyCsrf,
  requirePasswordWhenChangingEmail,
  (req, res) => {
    const { email, bio } = req.body;
    // TODO: persist to DB; here we just echo back
    res.json({ ok: true, updated: { email, bio } });
  }
);

// Fallback to index.html
app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

app.listen(PORT, () => console.log(`Secure app running at ${ORIGIN}`));
