import express from "express";

const app = express();

app.get("/", (req, res) => {
  res.send("Alghalbi Law System is running ✅");
});

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
