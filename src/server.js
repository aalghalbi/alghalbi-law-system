import "dotenv/config";
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

app.set("view engine", "ejs");
app.set("views", new URL("../views", import.meta.url).pathname);

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

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

// ===== Auth =====
app.get("/register", (req, res) => {
  res.render("register", { error: null, allowedDomain });
});

app.post("/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const name = String(req.body.name || "").trim() || null;
    const password = String(req.body.password || "");

    if (!isAllowedEmail(email)) {
      return res
        .status(400)
        .render("register", {
          error: `التسجيل متاح فقط لإيميلات @${allowedDomain}`,
          allowedDomain,
        });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .render("register", { error: "كلمة المرور لازم 8 أحرف على الأقل.", allowedDomain });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      return res
        .status(400)
        .render("register", { error: "هذا الإيميل مسجل مسبقًا. جرّب تسجيل الدخول.", allowedDomain });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: passwordHash,
      },
    });

    req.session.user = { id: user.id, email: user.email, name: user.name };
    return res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
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
      return res
        .status(400)
        .render("login", {
          error: `الدخول متاح فقط لإيميلات @${allowedDomain}`,
          allowedDomain,
        });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).render("login", { error: "بيانات الدخول غير صحيحة.", allowedDomain });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(400).render("login", { error: "بيانات الدخول غير صحيحة.", allowedDomain });
    }

    req.session.user = { id: user.id, email: user.email, name: user.name };
    return res.redirect("/dashboard");
  } catch (e) {
    console.error(e);
    return res.status(400).render("login", { error: "صار خطأ.", allowedDomain });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ===== Dashboard =====
app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

// ===== Clients (الموكلين) =====

// قائمة الموكلين
app.get("/clients", requireAuth, async (req, res) => {
  const clients = await prisma.client.findMany({
    where: { ownerId: req.session.user.id },
    orderBy: { createdAt: "desc" },
  });

  res.render("clients", { clients });
});

// صفحة إضافة موكل
app.get("/clients/new", requireAuth, (req, res) => {
  res.render("client_new", { error: null });
});

// حفظ موكل جديد
app.post("/clients/new", requireAuth, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const email = String(req.body.email || "").trim() || null;
    const phone = String(req.body.phone || "").trim() || null;
    const notes = String(req.body.notes || "").trim() || null;

    if (!fullName) {
      return res.status(400).render("client_new", { error: "اسم الموكل مطلوب." });
    }

    await prisma.client.create({
      data: {
        fullName,
        email,
        phone,
        notes,
        ownerId: req.session.user.id,
      },
    });

    return res.redirect("/clients");
  } catch (e) {
    console.error(e);
    return res.status(400).render("client_new", { error: "صار خطأ أثناء الحفظ." });
  }
});

// ===== Health check (اختياري) =====
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
