import "dotenv/config";
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";

const app = express();

app.set("view engine", "ejs");
app.set("views", new URL("../views", import.meta.url).pathname);

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);

// قاعدة بيانات بسيطة داخل الذاكرة (مؤقتًا فقط)
// لاحقًا ننقلها لـ PostgreSQL
const users = new Map(); // email -> { email, name, passwordHash }

const allowedDomain = process.env.ALLOWED_EMAIL_DOMAIN || "alghalbilaw.com";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isAllowedEmail(email) {
  return email.endsWith(`@${allowedDomain}`);
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null, allowedDomain });
});

app.post("/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const name = String(req.body.name || "").trim() || null;
    const password = String(req.body.password || "");

    if (!isAllowedEmail(email)) {
      return res.status(400).render("register", { error: `التسجيل متاح فقط لإيميلات @${allowedDomain}`, allowedDomain });
    }
    if (password.length < 8) {
      return res.status(400).render("register", { error: "كلمة المرور لازم 8 أحرف على الأقل.", allowedDomain });
    }
    if (users.has(email)) {
      return res.status(400).render("register", { error: "هذا الإيميل مسجل مسبقًا. جرّب تسجيل الدخول.", allowedDomain });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    users.set(email, { email, name, passwordHash });

    req.session.user = { email, name };
    return res.redirect("/dashboard");
  } catch (e) {
    return res.status(400).render("register", { error: "صار خطأ.", allowedDomain });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null, allowedDomain });
});

app.post("/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!isAllowedEmail(email)) {
      return res.status(400).render("login", { error: `الدخول متاح فقط لإيميلات @${allowedDomain}`, allowedDomain });
    }

    const user = users.get(email);
    if (!user) {
      return res.status(400).render("login", { error: "بيانات الدخول غير صحيحة.", allowedDomain });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).render("login", { error: "بيانات الدخول غير صحيحة.", allowedDomain });
    }

    req.session.user = { email: user.email, name: user.name };
    return res.redirect("/dashboard");
  } catch {
    return res.status(400).render("login", { error: "صار خطأ.", allowedDomain });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
