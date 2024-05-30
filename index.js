const express = require("express");
const app = express();
const User = require("./models/user");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

mongoose
  .connect(
    "mongodb+srv://pikachuzombie2:06Ax9gKfdu4gtNTE@therock.rqgcwza.mongodb.net/",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(() => {
    console.log("MONGO CONNECTION OPEN!!!");
  })
  .catch((err) => {
    console.log("OH NO MONGO CONNECTION ERROR!!!!");
    console.log(err);
  });

app.set("view engine", "ejs");
app.set("views", "views");

app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: "notagoodsecret" }));

const requireLogin = (req, res, next) => {
  if (!req.session.user_id) {
    return res.redirect("/login");
  }
  next();
};

let transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  service: "Gmail",

  auth: {
    user: "j67506219@gmail.com",
    pass: "mqnhgqztvontdmqa",
  },
});

// Home page
app.get("/", (req, res) => {
  res.send("THIS IS THE HOME PAGE");
});

// Register routes
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 12); // Hash password
  const user = new User({ username, password: hashedPassword, email }); // Save hashed password
  await user.save();
  req.session.user_id = user._id;
  res.redirect("/");
});

// Login routes
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find user by username
    const user = await User.findOne({ username });

    if (!user) {
      // User not found
      return res.redirect("/login");
    }

    // Compare hashed password with received password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      // Passwords match, log in the user
      req.session.user_id = user._id;
      return res.redirect("/secret");
    } else {
      // Passwords don't match
      return res.redirect("/login");
    }
  } catch (error) {
    // Error occurred during login
    console.error("Login error:", error);
    return res.redirect("/login");
  }
});

// Logout route
app.post("/logout", (req, res) => {
  req.session.user_id = null;
  res.redirect("/login");
});

// Secret routes
app.get("/secret", requireLogin, (req, res) => {
  res.render("secret");
});

app.get("/topsecret", requireLogin, (req, res) => {
  res.send("TOP SECRET!!!");
});

// Reset Password Request Form
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/forgot-password");
  }

  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  await user.save();

  const resetURL = `http://${req.headers.host}/reset-password/${token}`;
  console.log(resetURL);
  //   console.log(email);
  //   res.send("email sent");

  const mailOptions = {
    to: email,
    subject: "Password Reset",
    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                 Please click on the following link, or paste this into your browser to complete the process:\n\n
                 ${resetURL}\n\n
                 If you did not request this, please ignore this email and your password will remain unchanged.\n`,
  };

  transporter.sendMail(mailOptions, (err, response) => {
    if (err) {
      console.error("There was an error: ", err);
    } else {
      //   res.redirect("/forgot-password");
      res.send("email sent");
    }
  });
});

// Reset Password Form
app.get("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.redirect("/forgot-password");
  }

  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.redirect("/forgot-password");
  }

  const { password } = req.body;
  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (isPasswordValid) {
    // Passwords match, so the user is trying to reset to the same password
    // You can choose to handle this case or simply ignore it
    return res.redirect("/login");
  }

  // Hash the new password
  const hashedPassword = await bcrypt.hash(password, 12);

  // Update the user's password with the new hashed password
  user.password = hashedPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.redirect("/login");
});

app.listen(3000, () => {
  console.log("SERVING YOUR APP!");
});
