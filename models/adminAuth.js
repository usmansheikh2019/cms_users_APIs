const sequelize = require("../src/db/connection");
module.exports = (sequelize, DataTypes) => {
  const Auth_admin = sequelize.define("authAdmin", {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      allowNull: false,
      primaryKey: true,
    },
    adminId: {
      type: DataTypes.UUID,
      allowNull: false,
    },
    refreshToken: {
      type: DataTypes.STRING,
    },
  });
  return Auth_admin;
};
