import "dotenv/config";
import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

/* ================== إعدادات أساسية ================== */
app.set("view engine", "ejs");
app.set("views", new URL("../views", import.meta.url).pathname);
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);

/* ================== أدوات مساعدة ================== */
const allowedDomain = process.env.ALLOWED_EMAIL_DOMAIN;

const normalizeEmail = (email) =>
  String(email || "").trim().toLowerCase();

const isAllowedEmail = (email) =>
  email.endsWith(`@${allowedDomain}`);

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login");
  next();
};

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

/* ================== الصفحة الرئيسية ================== */
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.redirect("/login");
});

/* ================== التسجيل ================== */
app.get("/register", (req, res) => {
  res.render("register", { error: null, allowedDomain });
});

app.post("/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const name = req.body.name?.trim() || null;
    const password = req.body.password || "";

    if (!isAllowedEmail(email)) {
      return res.render("register", {
        error: `مسموح فقط بإيميلات @${allowedDomain}`,
        allowedDomain
      });
    }

    if (password.length < 8) {
      return res.render("register", {
        error: "كلمة المرور 8 أحرف على الأقل",
        allowedDomain
      });
    }

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists) {
      return res.render("login", {
        error: "الحساب موجود مسبقاً",
        allowedDomain
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email, name, password: passwordHash }
    });

    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("register", { error: "صار خطأ", allowedDomain });
  }
});

/* ================== تسجيل الدخول ================== */
app.get("/login", (req, res) => {
  res.render("login", { error: null, allowedDomain });
});

app.post("/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password || "";

    if (!isAllowedEmail(email)) {
      return res.render("login", {
        error: `مسموح فقط بإيميلات @${allowedDomain}`,
        allowedDomain
      });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.render("login", {
        error: "بيانات الدخول غير صحيحة",
        allowedDomain
      });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.render("login", {
        error: "بيانات الدخول غير صحيحة",
        allowedDomain
      });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("login", { error: "صار خطأ", allowedDomain });
  }
});

/* ================== تسجيل الخروج ================== */
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ================== Dashboard ================== */
app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

/* ================== الموكلين ================== */

// عرض الموكلين
app.get("/clients", requireAuth, async (req, res) => {
  const clients = await prisma.client.findMany({
    where: { ownerId: req.session.user.id },
    orderBy: { createdAt: "desc" }
  });
  res.render("clients", { clients });
});

// صفحة إضافة موكل
app.get("/clients/new", requireAuth, (req, res) => {
  res.render("client_new", { error: null });
});

// حفظ موكل
app.post("/clients/new", requireAuth, async (req, res) => {
  try {
    const { fullName, email, phone, notes } = req.body;

    if (!fullName?.trim()) {
      return res.render("client_new", { error: "اسم الموكل مطلوب" });
    }

    await prisma.client.create({
      data: {
        fullName: fullName.trim(),
        email: email?.trim() || null,
        phone: phone?.trim() || null,
        notes: notes?.trim() || null,
        ownerId:
