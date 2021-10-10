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
      expiresIn: "15min",
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
      res.status(403).json({ error: "Invalid/Expired Access Token" });
    } else if (e.message === "jwt expired") {
      res.status(401).json({ error: "Access Token has expired" });
    } else res.status(500).json({ error: e.message });
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

// Get all orders
exports.getOrders = async function (req, res) {
  try {
    const orders = await sequelize.query(`SELECT * FROM ws_orders`);
    if (!orders[0].length) {
      return res.status(404).json({ message: "No orders yet!" });
    }
    res.status(200).json(orders[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Get oder by id
exports.getOrderById = async function (req, res) {
  try {
    const orderId = await req.body.orderId;
    if (!orderId) {
      return res.status(400).json({ message: "Please enter orderId" });
    }
    if (!Number.isInteger(orderId) || orderId < 0) {
      return res.status(400).json({ message: "Invalid order ID" });
    }
    const order = await sequelize.query(
      `SELECT * FROM ws_orders WHERE PKOrderID = ${orderId}`
    );
    if (!order[0].length) {
      return res
        .status(404)
        .json({ message: `No order found with ID: ${orderId}` });
    }
    res.status(200).json(order[0][0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Get all customers
exports.getCustomers = async function (req, res) {
  try {
    const customers = await sequelize.query(`SELECT * FROM ws_customers`);
    if (!customers[0].length) {
      return res.status(404).json({ message: "No customers yet!" });
    }
    for (let index = 0; index < customers[0].length; index++) {
      delete customers[0][index].Password;
      delete customers[0][index].PasswordRecoveryCode;
      delete customers[0][index].PasswordRecoveryCodeExpire;
    }
    res.status(200).json(customers[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Get customer by ID
exports.getCustomerById = async function (req, res) {
  try {
    const customerId = await req.body.customerId;
    if (!customerId) {
      return res.status(400).json({ message: "Please enter customerId" });
    }
    if (!Number.isInteger(customerId) || customerId < 0) {
      return res.status(400).json({ message: "Invalid customer ID" });
    }
    const customer = await sequelize.query(
      `SELECT * FROM ws_customers WHERE PKCustomerID = ${customerId}`
    );
    if (!customer[0].length) {
      res
        .status(404)
        .json({ message: `No customer found with customerId: ${customerId}` });
    }
    delete customer[0][0].Password;
    delete customer[0][0].PasswordRecoveryCode;
    delete customer[0][0].PasswordRecoveryCodeExpire;
    res.status(200).send(customer[0][0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
