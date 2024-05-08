const User = require("../models/User");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const router = express.Router();
const nodemailer = require("nodemailer");
require("dotenv").config();

// Function to generate a JWT token
function generateToken(user) {
  const payload = {
    id: user._id,
    email: user.email,
  };

  const secretKey = process.env.JWT_SECRET;
  const accessTokenOptions = {
    expiresIn: "1h", // Token expiration time
  };
  const refreshTokenOptions = {
    expiresIn: "7d", // Refresh token expiration time
  };

  const accessToken = jwt.sign(payload, secretKey, accessTokenOptions);
  const refreshToken = jwt.sign(payload, secretKey, refreshTokenOptions);

  return { accessToken, refreshToken };
}
// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[0];

  if (token == null) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token expired" });
      }
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000);
};

const sendOTP = async (otp, email) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      secure: true,
      port: 465,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    let mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "OTP for email verification",
      text: `Your OTP is ${otp}`,
    };
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Error sending OTP:", error);
    throw Error(error);
  }
};

router.post("/register", async (req, res) => {
  const userData = req.body;
  try {
    const userExists = await User.findOne({ email: userData.email });
    if (userExists) {
      return res.status(400).json({ errors: ["User already exists"] });
    }
    const OTP = generateOTP();
    console.log(OTP);
    // await sendOTP(OTP, userData.email);
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(userData.password, saltRounds);
    userData.password = hashedPassword;
    userData.otp = OTP;
    const user = await User.create(userData);
    res.status(201).json(user);
    console.log("User created successfully");
  } catch (error) {
    if (error.name === "ValidationError") {
      const validationErrors = Object.values(error.errors).map(
        (err) => err.message
      );
      res.status(400).json({ errors: validationErrors });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (user.otp !== otp) {
      return res.status(401).json({ error: "Invalid OTP" });
    }
    user.email_verified = true;
    user.otp = null;
    await user.save();
    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/resend-otp", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const OTP = generateOTP();
    console.log(OTP);
    // await sendOTP(OTP, email);
    user.otp = OTP;
    await user.save();
    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const accessToken = generateToken(user);
    res.status(200).json({ message: "Login successfully", token: accessToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const OTP = generateOTP();
    console.log(OTP);
    // await sendOTP(OTP, email);
    user.otp = OTP;
    await user.save();
    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/reset-password", async (req, res) => {
  const { email, password, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    if (user.otp !== otp) {
      return res.status(401).json({ error: "Invalid OTP" });
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    user.password = hashedPassword;
    user.otp = null;
    await user.save();
    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/logout", (req, res) => {
  res.status(200).json({ message: "User Logout successfully" });
});

router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -otp");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const accessToken = generateToken(user);
    res
      .status(200)
      .json({ message: "Token refreshed successfully", token: accessToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
