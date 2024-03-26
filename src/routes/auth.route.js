const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth.controller.js");

router.post("/signup", authController.signUpUser);
router.get("/me", authController.getMe);
router.post("/login", authController.loginUser);
router.post("/logout", authController.logoutUser);

module.exports = router