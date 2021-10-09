const express = require("express");
const route = express();
const controller = require("../controller/admin/controller");

//All admin routes here

// Admin login
// Get refresh and access token in response here
route.post("/login", controller.login);

// Renew the access token here
// Send valid refresh token and get new access token in response
// And then send the request with valid access token
route.post("/renewAccessToken", controller.renewAccessToken);

// Change password
route.patch(
  "/changePassword",
  controller.authenticateAdmin,
  controller.changePassword
);

// Admin logout
route.post("/logout", controller.authenticateAdmin, controller.logout);

module.exports = route;
