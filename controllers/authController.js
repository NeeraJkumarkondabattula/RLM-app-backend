const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const OTP = require("../models/otpModel");
const transporter = require("../config/mailer");

// Generate OTP (returns string)
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// Request OTP
exports.requestOTP = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  try {
    const otp = generateOTP(); // string
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // remove any previous OTPs for this email
    await OTP.deleteMany({ email });

    // store as string (defensive)
    await OTP.create({
      email,
      otp: String(otp),
      expiresAt,
      createdAt: new Date(),
    });

    // NOTE: for development you can console.log the OTP here
    console.log(
      `DEBUG - OTP for ${email}: ${otp} (expires ${expiresAt.toISOString()})`
    );

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    return res.json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error("REQUEST OTP ERROR:", error);
    return res.status(500).json({ message: "Failed to send OTP" });
  }
};

// Register
exports.register = async (req, res) => {
  const { email, password, otp, firstname, lastname, dob, mobile } = req.body;

  if (!email || (!password && !otp)) {
    return res
      .status(400)
      .json({ message: "Email and password OR OTP are required" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    let hashedPassword = null;

    if (password) {
      const salt = await bcrypt.genSalt(10);
      hashedPassword = await bcrypt.hash(password, salt);
    } else if (otp) {
      // fetch latest OTP record for this email
      const record = await OTP.findOne({ email }).sort({ createdAt: -1 });

      if (!record) {
        return res.status(400).json({ message: "Invalid OTP" });
      }

      if (String(record.otp).trim() !== String(otp).trim()) {
        return res.status(400).json({ message: "Invalid OTP" });
      }

      if (record.expiresAt < new Date()) {
        return res.status(400).json({ message: "OTP expired" });
      }

      await OTP.deleteMany({ email });
    }

    // ✅ Pass all required fields here
    const user = await User.create({
      email,
      password: hashedPassword, // null if OTP used
      firstname,
      lastname,
      dob,
      mobile,
    });

    const token = jwt.sign(
      { userId: user._id, email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({ token, message: "Registration successful" });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    return res.status(500).json({ message: "Registration failed" });
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
      const record = await OTP.findOne({ email }).sort({ createdAt: -1 });

      if (
        record &&
        String(record.otp).trim() === String(otp).trim() &&
        record.expiresAt >= new Date()
      ) {
        isAuthenticated = true;
        await OTP.deleteMany({ email });
      }
    }

    if (!isAuthenticated) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, email },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    return res.json({ token, message: "Login successful" });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({ message: "Login failed" });
  }
};
