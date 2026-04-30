import bcrypt from "bcryptjs";
import { signToken } from "../utils/jwt.js";
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
/**
 * TODO: Register a new user
 *
 * 1. Extract name, email, password from req.body
 * 2. Check if user with email already exists
 *    - If yes: return 409 with { error: { message: "Email already exists" } }
 * 3. Create new user (password will be hashed by pre-save hook)
 * 4. Return 201 with { user } (password excluded by default)
 */
// normal hasing function for hash token
const haseToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

export async function register(req, res, next) {
  try {
    // Your code here
    const { name, email, password } = req.body;
    if (
      !name ||
      !email ||
      !password ||
      [name, email, password].some((field) => field?.trim() === "")
    ) {
      return res
        .status(400)
        .json({ error: { message: "All fields are required" } });
    }

    // console.log(name, email, password);
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        error: {
          message: "Email already exists",
        },
      });
    }
    // console.log(existingUser);
    const user = await User.create({ name, email, password });
    const userObject = user.toObject();
    delete userObject.password;
    return res.status(201).json({
      // remove the password field from the user object before sending the response
      user: userObject,
      message: "User registered successfully",
    });
  } catch (error) {
    next(error);
  }
}

/**
 * TODO: Login user
 *
 * 1. Extract email, password from req.body
 * 2. Find user by email (use .select('+password') to include password field)
 * 3. If no user found: return 401 with { error: { message: "Invalid credentials" } }
 * 4. Compare password using bcrypt.compare(password, user.password)
 * 5. If password wrong: return 401 with { error: { message: "Invalid credentials" } }
 * 6. Generate JWT token with payload: { userId: user._id, email: user.email, role: user.role }
 * 7. Return 200 with { token, user } (exclude password from user object)
 */
export async function login(req, res, next) {
  try {
    // Your code here
    const { email, password } = req.body;
    console.log(email, password);
    if (
      !email ||
      !password ||
      [email, password].some((field) => field?.trim() === "")
    ) {
      return res.status(400).json({
        error: { message: "All fields are required" },
      });
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({
        error: {
          message: "Invalid credentials",
        },
      });
    }

    const passwordCheck = await bcrypt.compare(password, user.password);
    if (!passwordCheck) {
      return res.status(401).json({
        error: {
          message: "Invalid credentials",
        },
      });
    }

    const accessToken =  signToken({
      userId: user._id,
      email: user.email,
      role: user.role,
    });
    const refreshToken =  jwt.sign(
      { _id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );
    //save the refresh token to db
    user.refreshToken = haseToken(refreshToken);
    await user.save({ validateBeforeSave: false });

    const userObj = user.toObject();
    delete userObj.password;
    delete userObj.refreshToken;

    return res.status(200).json({
      message: "User login success ",
      user: userObj,
      token: accessToken,
      refreshToken,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * TODO: Get current user
 *
 * 1. req.user is already set by auth middleware
 * 2. Return 200 with { user: req.user }
 */
export async function me(req, res, next) {
  try {
    // Your code here
  } catch (error) {
    next(error);
  }
}
