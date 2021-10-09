require("./db/connection");
const db = require("../models");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const adminRoutes = require("./routes/adminRoutes");
app.use(express.json());
app.use("/admin", adminRoutes);

// app.patch("/admin/changePassword", async (req, res) => {
//   try {
//     const modification = await req.body;
//     const newPassword = await bcrypt.hash(modification.Password, 8);
//     const sql = `UPDATE cms_users SET Password = '${newPassword}' WHERE EmailAddress = '${modification.email}'`;
//     const result = db.query(sql, (err, result) => {
//       if (err) res.status(400).json({ message: err.message });
//       return res.status(201).json(result);
//     });
//   } catch (e) {
//     res.status(500).json({ error: e.message });
//   }
// });

db.sequelize
  .sync()
  .then(req => {
    app.listen(3000, () => {
      console.log("listening on port 3000...");
    });
  })
  .catch(e => {
    console.log({ error: e.message });
  });
