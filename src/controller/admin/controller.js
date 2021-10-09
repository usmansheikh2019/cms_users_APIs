const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { sequelize } = require("../../../models");
const { QueryTypes } = require("sequelize");
const adminAuthModel = sequelize.import("../../../models/adminAuth");
exports.login = async function (req, res) {
  try {
    const email = await req.body.email;
    const password = await req.body.password;
    if (!email) {
      return res.status(400).json({ message: "Please enter your email" });
    }
    if (!password) {
      return res.status(400).json({ message: "Please enter your password" });
    }
    const admin = await verifyCredentials(email, password);
    if (!admin) {
      res.status(404).json({ message: "Incorrect email or password" });
    }
    const tokens = await generateAuthTokens(admin.PKUserID);
    const Admin = {
      email: admin.EmailAddress,
      fname: admin.FirstName,
      lname: admin.LastName,
      PKUserID: admin.PKUserID,
      status: admin.Status,
    };
    res.status(200).json({ Admin, tokens });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

async function verifyCredentials(email, password) {
  const admin = await sequelize.query(
    `SELECT * FROM cms_users WHERE EmailAddress = '${email}'`,
    { type: QueryTypes.SELECT }
  );
  if (!admin.length) {
    return false;
  }
  const passwordMatches = await bcrypt.compare(password, admin[0].Password);
  if (!passwordMatches) {
    return false;
  }
  if (passwordMatches) {
    return admin[0];
  }
}

async function generateAuthTokens(adminId) {
  try {
    // Expieres in 1 year
    const refreshToken = jwt.sign({ id: adminId }, "refreshTokenSecretKey", {
      expiresIn: "1y",
    });

    // Expires in 15 minutes
    const accessToken = jwt.sign({ id: adminId }, "accessTokenSecretKey", {
      expiresIn: "3min",
    });

    const authAdmin = await adminAuthModel.create({
      adminId: adminId,
      refreshToken: refreshToken,
    });
    return {
      refreshToken: authAdmin.refreshToken,
      accessToken: accessToken,
    };
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Admin authentication
// Only work when access token is not expired
// If access token is expired, don't send it here
// Send Expired access tokens to the /renewAccessToken route to get new access token
exports.authenticateAdmin = async function (req, res, next) {
  try {
    const accessToken = req.header("Authorization").replace("Bearer ", "");
    const decodedToken = jwt.verify(accessToken, "accessTokenSecretKey");
    const id = decodedToken.id;
    const admin = await sequelize.query(
      `SELECT * FROM cms_users WHERE PKUserID = ${id}`
    );
    req.accessToken = accessToken;
    req.admin = admin[0];
    next();
  } catch (e) {
    if (e.message === "invalid signature") {
      res.status(403).json({ error: "Invalid Access Token" });
    }
    res.status(500).json({ error: e.message });
  }
};

// Renew access token
exports.renewAccessToken = async function (req, res) {
  try {
    const refreshToken = await req.body.refreshToken;
    const decodedToken = jwt.verify(refreshToken, "refreshTokenSecretKey");
    const id = parseInt(decodedToken.id, 10);
    const authAdmin = await adminAuthModel.findOne({
      where: {
        adminId: id,
      },
    });
    if (!authAdmin) {
      res.status(403).json({ alert: "Invalid Refresh token" });
    }
    const NewAccessToken = jwt.sign({ id: id }, "accessTokenSecretKey", {
      expiresIn: "10min",
    });
    res.status(200).json({ NewAccessToken: NewAccessToken });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Change password
exports.changePassword = async function (req, res) {
  try {
    const admin = await req.admin;
    const oldPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
    const retypeNewPassword = req.body.retypeNewPassword;
    if (!oldPassword) {
      return res
        .status(400)
        .json({ message: "Please enter your old password" });
    }
    if (!newPassword) {
      res.status(400).json({ message: "Please enter your new password" });
    }
    if (!retypeNewPassword) {
      return res
        .status(400)
        .json({ message: "Please retype your new password" });
    }
    if (newPassword.length > 16 || newPassword.length < 5) {
      res
        .status(400)
        .json({ message: "Password between 5 to 16 characters is acceptable" });
    }
    if (newPassword !== retypeNewPassword) {
      return res.status(400).json({ message: "Password don't match" });
    }
    const passwordMatches = await bcrypt.compare(
      oldPassword,
      admin[0].Password
    );
    if (!passwordMatches) {
      return res.status(400).json({ message: "Incorrect old password" });
    }
    const newHashedPassword = await bcrypt.hash(newPassword, 8);
    const updatedProfile = await sequelize.query(
      `UPDATE cms_users SET Password = '${newHashedPassword}' WHERE PKUserID = ${admin[0].PKUserID}`
    );
    res.status(200).json({ message: "Password has changed" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Logout admin
exports.logout = async function (req, res) {
  try {
    const admin = await req.admin;
    const refreshTokenFromClient = await req.body.refreshToken;
    const decodedToken = jwt.verify(
      refreshTokenFromClient,
      "refreshTokenSecretKey"
    );
    const authAdmin = await adminAuthModel.findOne({
      where: {
        refreshToken: refreshTokenFromClient,
        adminId: decodedToken.id,
      },
    });
    if (!authAdmin) {
      res.status(403).json({ error: "Invalid Access Token" });
    }
    await authAdmin.destroy();
    res.status(200).json({
      message: `${admin[0].FirstName} ${admin[0].LastName} is logged out`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
