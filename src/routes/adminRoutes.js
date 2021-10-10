const express = require("express");
const { appendFile } = require("fs");
const route = express();
const controller = require("../controller/admin/controller");

// Admin routes

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

// Get all orders
route.get("/orders", controller.authenticateAdmin, controller.getOrders);

// Get order by ID
route.get(
  "/getOrderById",
  controller.authenticateAdmin,
  controller.getOrderById
);

// Get all customers
route.get("/customers", controller.authenticateAdmin, controller.getCustomers);

// Get customer by ID
route.get(
  "/getCustomerById",
  controller.authenticateAdmin,
  controller.getCustomerById
);

module.exports = route;
