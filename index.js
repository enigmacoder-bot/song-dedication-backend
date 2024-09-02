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
import jwt from "jsonwebtoken";
dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const server = http.createServer(app);

const successSVG = `<svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 122.88 121.86"><defs><style>.cls-1{fill:#10a64a;}.cls-1,.cls-2,.cls-3,.cls-4{fill-rule:evenodd;}.cls-2{fill:#0bb34b;}.cls-3{fill:#fff;}.cls-4{fill:#303030;}</style></defs><title>approve</title><path class="cls-1" d="M61.44,0a14.05,14.05,0,0,1,8.45,2.65c3.3,2.1,7,6.23,11.61,8.86C88,15.21,99.9,10.12,106,19.21c3.57,5.31,3.73,9.46,4,13.57.29,4.43,1.07,8.51,5.6,14.51,7.51,9.93,9.07,16.54,5.2,23.43-2.63,4.69-8.19,7.3-9.47,10.28-2.74,6.33.29,11.1-3.46,18.47a19.66,19.66,0,0,1-12,10.21c-4.5,1.46-9-.64-12.63.87-6.34,2.67-11,8.86-16.06,10.42a19.47,19.47,0,0,1-11.64,0c-5-1.56-9.72-7.75-16.06-10.42-3.61-1.51-8.13.59-12.63-.87A19.66,19.66,0,0,1,15,99.47C11.23,92.1,14.26,87.33,11.52,81,10.24,78,4.68,75.41,2,70.72c-3.87-6.89-2.3-13.5,5.21-23.43,4.53-6,5.31-10.08,5.6-14.51.26-4.11.43-8.26,4-13.57,6.13-9.09,18.08-4,24.53-7.69C46,8.89,49.69,4.76,53,2.66A14.05,14.05,0,0,1,61.44,0Z"/><path class="cls-2" d="M111,38.83a27,27,0,0,0,4.59,8.46c7.51,9.93,9.07,16.54,5.2,23.43-2.63,4.69-8.19,7.3-9.47,10.28-2.74,6.33.29,11.1-3.46,18.47a19.68,19.68,0,0,1-12,10.21c-4.5,1.45-9-.64-12.63.87-6.34,2.67-11,8.85-16.06,10.42a19.47,19.47,0,0,1-11.64,0c-5-1.57-9.72-7.75-16.06-10.42-3.61-1.51-8.13.58-12.63-.87A19.66,19.66,0,0,1,15,99.47a18.15,18.15,0,0,1-2-6.91l98-53.73Z"/><path class="cls-3" d="M61.26,25.5A36.37,36.37,0,1,1,24.89,61.87,36.37,36.37,0,0,1,61.26,25.5Z"/><path class="cls-4" d="M51.41,54.61l7.12,6.71L72.81,46.8c1.41-1.43,2.3-2.58,4-.79l5.67,5.79c1.85,1.84,1.75,2.91,0,4.63L61.75,76.83c-3.69,3.62-3,3.85-6.8.12L41.88,64A1.65,1.65,0,0,1,42,61.41L48.6,54.6c1-1,1.79-1,2.81,0Z"/></svg>`;

const io = new socketIo.Server(server, {
  cors: {
    origin: "http://localhost:3000", // Change this to your frontend URL
    methods: ["GET", "POST"],
    allowedHeaders: ["my-custom-header"],
    credentials: true,
  },
});

const PORT = process.env.PORT || 5000;

// MongoDB Connection
mongoose
  .connect("mongodb+srv://sumanth:Hello123@cluster0.aq1npql.mongodb.net/", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// Define MongoDB Schema
const songRequestSchema = new mongoose.Schema({
  name: String,
  artist: String,
  requestedBy: String,
  message: String,
  isDedication: Boolean,
  dedicatedTo: String,
  songLink: String,
});

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String, // hashed password
  verified: Boolean,
});

const userVerificationSchema = new mongoose.Schema({
  userId: String,
  uniqueString: String,
  createdDate: Date,
  expiresDate: Date,
});

const resetPasswordSchema = new mongoose.Schema({
  userId: String,
  resetString: String,
  createdDate: Date,
  expiresDate: Date,
});

const User = mongoose.model("User", userSchema);
const SongRequest = mongoose.model("SongRequest", songRequestSchema);
const UserVerification = mongoose.model(
  "UserVerification",
  userVerificationSchema
);
const ResetPassword = mongoose.model("ResetPassword", resetPasswordSchema);

let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASSWORD,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.log("Error", error);
  } else {
  }
});

const sendVerificationMail = async ({ _id, email }, res) => {
  try {
    const currentURL = "http://localhost:5000/";
    const uniqueString = uuidv4() + _id;

    // Hash the unique string
    const hashedUniqueString = await bcrypt.hash(uniqueString, 10);

    // Create a new UserVerification document
    const newVerification = new UserVerification({
      userId: _id,
      uniqueString: hashedUniqueString,
      createdDate: Date.now(),
      expiresDate: Date.now() + 21600000, // 6 hours in milliseconds
    });

    // Save the verification document
    await newVerification.save();

    // Set up the email options
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Verify Your Email",
      html: `<p>Verify your email address to complete the signup and log in to your account.</p>
             <p>This link expires in 5 hours.</p>
             <p>Click <a href="${currentURL}verify/${_id}/${uniqueString}">here</a> to proceed.</p>`,
    };

    // Send the verification email
    await transporter.sendMail(mailOptions);

    // res.json({
    //   status: 'PENDING',
    //   message: 'Verification email sent.',
    // });
  } catch (error) {
    console.error("Error in sendVerificationMail:", error);

    // res.json({
    //   status: 'FAILED',
    //   message: 'An error occurred during the verification process.',
    // });
  }
};

//protect dedication page
//io middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error("Authentication error"));
  }

  try {
    const decoded = jwt.verify(token, "your-secret-key");
    socket.user = decoded; // Attach the decoded user information to the socket instance
    next();
  } catch (error) {
    return next(new Error("Authentication error"));
  }
});

// Socket.IO
io.on("connection", (socket) => {
  console.log("New client connected");

  // Send current song requests to client on connection
  SongRequest.find({})
    .then((requests) => {
      socket.emit("initialRequests", requests);
    })
    .catch((err) => {
      console.error(err);
    });

  // Handle new song request
  socket.on("newRequest", async (data) => {
    try {
      const request = new SongRequest(data);
      await request.save();
      io.emit("newRequest", request);
    } catch (err) {
      console.error(err);
    }
  });

  // Handle request deletion
  socket.on("deleteRequest", async (requestId, callback) => {
    try {
      await SongRequest.findByIdAndDelete(requestId);
      io.emit("requestDeleted", requestId); // Notify all clients about the deletion
      callback({ success: true });
    } catch (err) {
      console.error("Error deleting request:", err);
      callback({ success: false });
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected");
  });
});

// route protection

const createToken = (_id) => {
  return jwt.sign({ _id }, "Song Dedication 222", { expiresIn: "3hr" });
};

// Signup Route
app.post("/signup", async (req, res) => {
  console.log(req.body);
  try {
    const { username, email, password } = req.body;

    // Check if username, email, and password are present in the request body
    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      verified: false,
    });
    await newUser.save().then((result) => {
      console.log("New User Saved.", result);
      sendVerificationMail(result, res);
    });

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    if (!user.verified) {
      return res.status(404).json({ status: 404, error: "User Not Verified." });
    }
    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    // Generate JWT token
    const token = createToken(user._id);

    // Return the token in the response
    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;
  console.log("Verification Link ");
  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        if (expiresAt < Date.now()) {
          UserVerification.deleteOne({ userId })
            .then(() => {
              User.deleteOne({ _id: userId })
                .then()
                .catch((error) => {
                  console.log(error);
                });
            })
            .catch((error) => {
              console.log(error);
            });
        }
        //user verification record is valid
        else {
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                //verify the user
                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    //delete verification record once the user is verified.
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        // user is verified.
                        res.send(`<!DOCTYPE html>
                  <html lang="en">
                  <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verification Success</title>
                    <style>
                      body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 50px;
                        background-color: #f4f4f4;
                        color: #333;
                      }
                      h1 {
                        color: #4CAF50;
                      }
                      .container {
                        max-width: 600px;
                        margin: auto;
                        background: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                      }
                      svg {
                        width: 100px;
                        height: 100px;
                        margin-bottom: 20px;
                      }
                    </style>
                  </head>
                  <body>
                    <div class="container">
                      ${successSVG}
                      <h1>Email Verification Successful!</h1>
                      <p>Your email has been successfully verified. You can now log in to your account.</p>
                    </div>
                  </body>
                  </html>
                `);
                        // res.status(200).json({ success: 'User Verification Success.' });
                      })
                      .catch((error) => {
                        console.log(error);
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                  });
              } else {
              }
            })
            .catch((error) => {
              console.log(error);
            });
        }
      } else {
      }
    })
    .catch((error) => {
      console.log(error);
    });
});

//Reset Password

app.post("/requestResetpassword", (req, res) => {
  const { email, redirectUrl } = req.body;
  User.find({ email })
    .then((data) => {
      if (data.length) {
        if (!data[0].verified) {
          res.json({
            status: "FAILED",
            message: "Email is not verified. Please verify the email.",
          });
        } else {
          sendPasswordResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "FAILED",
          message: "Non-valid Email Id.",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "An error occurred during the reset password process.",
      });
    });
});

const sendPasswordResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;
  ResetPassword.deleteMany({ userId: _id })
    .then((result) => {
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Reset Your Password",
        html: `<p>We received a request to reset the password for your account.</p>
              <p>This link will expire in 5 hours.</p>
              <p>Click <a href="${
                redirectUrl + "/" + _id + "/" + resetString
              }">here</a> to reset your password.</p>
              <p>If you did not request a password reset, please ignore this email.</p>
`,
      };

      bcrypt
        .hash(resetString, 10)
        .then((hashedResetString) => {
          const newPasswordReset = new ResetPassword({
            userId: _id,
            resetString: hashedResetString,
            createdDate: Date.now(),
            expiresDate: Date.now() + 3600000,
          });

          newPasswordReset
            .save()
            .then(() => {
              transporter.sendMail(mailOptions).then(() => {
                res.json({
                  status: "PENDING",
                  message: "Password reset email sent.",
                });
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "An error occurred during the reset password",
              });
            });
        })
        .catch((error) => {
          console.log(error);
        });
    })
    .catch((error) => {
      console.log(error);
    });
};

app.post("/resetPassword", (req, res) => {
  let { userId, resetString, newPassword } = req.body;

  ResetPassword.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        const { expiresDate } = result[0];
        const hashedResetString = result[0].resetString;

        if (expiresDate < Date.now()) {
          ResetPassword.deleteOne({ userId })
            .then()
            .catch((error) => {
              console.log(error);
            });
        } else {
          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                bcrypt
                  .hash(newPassword, 10)
                  .then((hashedNewPassword) => {
                    //update the user password
                    User.updateOne(
                      { _id: userId },
                      { password: hashedNewPassword }
                    )
                      .then(() => {
                        //successful user delete
                        res.json({
                          status: "SUCCESS",
                          message: "Password has been reset successfully.",
                        });

                        ResetPassword.deleteOne({ userId })
                          .then()
                          .catch((error) => {
                            console.log(error);
                          });
                      })
                      .catch((error) => {
                        console.log(error);
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                  });
              } else {
                res.json({
                  status: "Failed",
                  message: "Invalid Password Reset Details Passed.",
                });
              }
            })
            .catch((error) => {
              console.log(error);
            });
        }
      }
    })
    .catch((error) => {
      console.log(error);
    });
});

// Start Server
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
