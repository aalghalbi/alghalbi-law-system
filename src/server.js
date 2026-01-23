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
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ===== Helpers =====
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

// ===== Auth =====
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.redirect("/login");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null, allowedDomain });
});

app.post("/register", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const name = req.body.name || null;
  const password = req.body.password || "";

  const usersCount = await prisma.user.count();

  if (usersCount > 0 && !isAllowedEmail(email)) {
    return res.render("register", {
      error: `التسجيل متاح فقط لإيميلات @${allowedDomain}`,
      allowedDomain,
    });
  }

  if (password.length < 8) {
    return res.render("register", {
      error: "كلمة المرور لازم 8 أحرف على الأقل",
      allowedDomain,
    });
  }

  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) {
    return res.render("register", {
      error: "هذا الإيميل مسجل مسبقًا",
      allowedDomain,
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: { email, name, password: passwordHash },
  });

  req.session.user = { id: user.id, email: user.email, name: user.name };
  res.redirect("/dashboard");
});

app.get("/login", (req, res) => {
  res.render("login", { error: null, allowedDomain });
});

app.post("/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = req.body.password || "";

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.render("login", { error: "بيانات الدخول غير صحيحة", allowedDomain });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    return res.render("login", { error: "بيانات الدخول غير صحيحة", allowedDomain });
  }

  req.session.user = { id: user.id, email: user.email, name: user.name };
  res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// ===== Dashboard =====
app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

// ===== Clients =====
app.get("/clients", requireAuth, async (req, res) => {
  const clients = await prisma.client.findMany({
    where: { ownerId: req.session.user.id },
    orderBy: { createdAt: "desc" },
  });

  res.render("clients", { clients });
});

app.get("/clients/new", requireAuth, (req, res) => {
  res.render("client_new", { error: null });
});

app.post("/clients/new", requireAuth, async (req, res) => {
  const { fullName, email, phone, notes } = req.body;

  if (!fullName) {
    return res.render("client_new", { error: "اسم الموكل مطلوب" });
  }

  await prisma.client.create({
    data: {
      fullName,
      email: email || null,
      phone: phone || null,
      notes: notes || null,
      ownerId: req.session.user.id,
    },
  });

  res.redirect("/clients");
});

// ===== Server =====
const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log("Server running on port", port);
});
