const express = require("express");
const {
  requestOTP,
  register,
  login,
} = require("../controllers/authController");

const router = express.Router();

router.post("/request-otp", requestOTP);
router.post("/register", register);
router.post("/login", login);

module.exports = router;
