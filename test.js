import express from "express";
import mongoose from "mongoose";
import http from "http";
import * as socketIo from "socket.io";
import bcrypt from "bcrypt";
import cors from "cors"; // Import cors middleware
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";

// Connect to MongoDB (Update with your connection string)
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const app = express();
app.use(cors()); // Use cors middleware
app.use(express.json());

const port = process.env.PORT || 5000;

// Middleware
//app.use(bodyParser.json());

// Mongoose Schema and Model
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Hash password before saving
adminSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

const Admin = mongoose.model("Admin", adminSchema);

// Admin Signup Endpoint
app.post("/adminSignup", async (req, res) => {
  const { username, email, password } = req.body;

  // Validate request
  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Create a new admin record
    const admin = new Admin({ username, email, password });
    await admin.save();

    res.status(201).json({ message: "Admin created successfully" });
  } catch (error) {
    console.error("Error creating admin:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
