import express from "express";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <h2>نظام إدارة القضايا - الغالبي</h2>
    <form method="POST" action="/login">
      <input name="email" placeholder="Email" />
      <button>تسجيل دخول</button>
    </form>
  `);
});

app.post("/login", (req, res) => {
  const email = req.body.email;

  if (!email || !email.endsWith("@alghalbilaw.com")) {
    return res.send("مسموح فقط بإيميل المكتب");
  }

  res.send("<h3>تم تسجيل الدخول بنجاح 🎉</h3>");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
