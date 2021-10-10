require("./db/connection");
const db = require("../models");
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const adminRoutes = require("./routes/adminRoutes");
app.use(express.json());
app.use("/admin", adminRoutes);

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
