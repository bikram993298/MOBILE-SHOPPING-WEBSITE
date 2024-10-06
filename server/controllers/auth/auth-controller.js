const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../../models/User");

// Register User
const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  try {
    // Log request data for debugging
    console.log("Registration request received:", req.body);

    // Check if user already exists
    const checkUser = await User.findOne({ email });
    if (checkUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with the same email! Please try again",
      });
    }

    // Hash the password
    const hashPassword = await bcrypt.hash(password, 12);

    // Create a new user instance
    const newUser = new User({
      userName,
      email,
      password: hashPassword,
    });

    // Save the new user to the database
    await newUser.save().catch(err => {
      console.error('Error saving new user:', err);
      return res.status(500).json({
        success: false,
        message: 'Failed to register user',
        error: err.message
      });
    });

    // Send a success response
    res.status(201).json({
      success: true,
      message: "Registration successful",
    });
  } catch (e) {
    // Log the full error details for debugging
    console.error("Error during registration:", e);
    res.status(500).json({
      success: false,
      message: "Some error occurred",
      error: e.message, // Optional: Include error message for more context
    });
  }
};

// Login User
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Log login request for debugging
    console.log("Login request received:", req.body);

    // Check if the user exists
    const checkUser = await User.findOne({ email });
    if (!checkUser) {
      return res.status(404).json({
        success: false,
        message: "User doesn't exist! Please register first",
      });
    }

    // Compare the password with the stored hash
    const checkPasswordMatch = await bcrypt.compare(password, checkUser.password);
    if (!checkPasswordMatch) {
      return res.status(401).json({
        success: false,
        message: "Incorrect password! Please try again",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: checkUser._id,
        role: checkUser.role,
        email: checkUser.email,
        userName: checkUser.userName,
      },
      "CLIENT_SECRET_KEY", // Replace with your real secret key
      { expiresIn: "60m" }
    );

    // Send login success response with the token
    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      token,
      user: {
        email: checkUser.email,
        role: checkUser.role,
        id: checkUser._id,
        userName: checkUser.userName,
      },
    });
  } catch (e) {
    // Log the full error details for debugging
    console.error("Error during login:", e);
    res.status(500).json({
      success: false,
      message: "Some error occurred",
      error: e.message,
    });
  }
};

// Logout User
const logoutUser = (req, res) => {
  res.clearCookie("token").json({
    success: true,
    message: "Logged out successfully!",
  });
};

// Auth Middleware (Using Authorization header)
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract token from Bearer

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, "CLIENT_SECRET_KEY"); // Replace with your real secret key
    req.user = decoded;
    next();
  } catch (error) {
    // Log any token verification errors
    console.error("Token verification error:", error);
    res.status(401).json({
      success: false,
      message: "Unauthorized user!",
      error: error.message,
    });
  }
};

module.exports = { registerUser, loginUser, logoutUser, authMiddleware };
