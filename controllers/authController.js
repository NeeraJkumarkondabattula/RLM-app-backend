const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const OTP = require("../models/otpModel");
const transporter = require("../config/mailer");

// Generate OTP
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// Request OTP
exports.requestOTP = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await OTP.deleteMany({ email });
    await OTP.create({ email, otp, expiresAt });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    res.json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

// Register
exports.register = async (req, res) => {
  const { email, password, otp } = req.body;
  if (!email || (!password && !otp)) {
    return res
      .status(400)
      .json({ message: "Email and password OR OTP are required" });
  }

  try {
    let existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    let hashedPassword;

    if (password) {
      // 🔑 Register with password
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    } else if (otp) {
      // 🔑 Register with OTP
      const record = await OTP.findOne({ email, otp: String(otp) }); // ensure string match
      if (!record) return res.status(400).json({ message: "Invalid OTP" });
      if (record.expiresAt < new Date())
        return res.status(400).json({ message: "OTP expired" });

      await OTP.deleteMany({ email });
    }

    const user = await User.create({
      email,
      password: hashedPassword || null,
    });

    const token = jwt.sign(
      { userId: user._id, email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, message: "Registration successful" });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ message: "Registration failed" });
  }
};

// Login
exports.login = async (req, res) => {
  const { email, password, otp } = req.body;
  if (!email || (!password && !otp)) {
    return res
      .status(400)
      .json({ message: "Email and password OR OTP are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    let isAuthenticated = false;

    if (password && user.password) {
      isAuthenticated = await bcrypt.compare(password, user.password);
    } else if (otp) {
      const record = await OTP.findOne({ email, otp: String(otp) }); // ensure string
      if (record && record.expiresAt >= new Date()) {
        isAuthenticated = true;
        await OTP.deleteMany({ email });
      }
    }

    if (!isAuthenticated)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, message: "Login successful" });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ message: "Login failed" });
  }
};
