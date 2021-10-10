const Sequelize = require("sequelize");

const sequelize = new Sequelize("db", "root", "044847", {
  host: "localhost",
  dialect: "mysql",
  operatorsAliases: 0,
});

//Testing connection
sequelize
  .authenticate()
  .then(() => {
    console.log("Connection has been established successfully.");
  })
  .catch(err => {
    console.error("Unable to connect to the database:", err);
  });

module.exports = sequelize;
