const router = require("express").Router();
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/Users");
const jwtSecret = process.env.JWT_SECRET;

router.get("/register", async (req, res) => {
  try {
    const { userStatus } = req;
    if (userStatus.loggedIn) return res.redirect("/");
    res.render("register");
  } catch (error) {
    res.render("error", {
      error: "Server side error occurred",
      message: error
    });
  }
});

router.post(
  "/register",
  
  async (req, res) => {
    try {
      const { userStatus } = req;
      if (userStatus.loggedIn) return res.redirect("/");
      const result = validationResult(req);
      if (!result.isEmpty())
        return res.render("error", {
          error: "Invalid request",
          message: "Please provide correct data"
        });
      const { username, email, password } = req.body;
      const usernameExist = await User.findOne({ username: username });
      const emailExist = await User.findOne({ email: email });
      if (usernameExist && emailExist)
        return res.render("error", {
          error: "Invalid request",
          message: "User with this username and email already registered"
        });
      if (usernameExist || emailExist)
        return res.render("error", {
          error: "Invalid request",
          message: `User with this ${
            usernameExist ? "username" : "email"
          } already registered`
        });
      const hashedPassword = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
      const newUser = await User.create({
        username: username,
        email: email,
        password: hashedPassword
      });
      const authToken = jwt.sign({ id: newUser.id.toString() }, jwtSecret);
      res.cookie("rtchat_auth_token", authToken, { maxAge: 604800000 });
      res.redirect("/");
    } catch (error) {
      res.render("error", {
        error: "Server side error occurred",
        message: error
      });
    }
  }
);

router.get("/login", async (req, res) => {
  try {
    const { userStatus } = req;
    if (userStatus.loggedIn) return res.redirect("/");
    res.render("login");
  } catch (error) {
    res.render("error", {
      error: "Server side error occurred",
      message: error
    });
  }
});

router.post(
  "/login",
 
  async (req, res) => {
    try {
      const { userStatus } = req;
      if (userStatus.loggedIn) return res.redirect("/");
      const result = validationResult(req);
      if (!result.isEmpty())
        return res.render("error", {
          error: "Invalid request",
          message: "Please provide correct data"
        });
      const { username, password } = req.body;
      const userExist = await User.findOne({ username: username });
      if (!userExist)
        return res.render("error", {
          error: "Invalid request",
          message: "Please provide correct credentials"
        });
      const passwordMatched = bcrypt.compareSync(password, userExist.password);
      if (!passwordMatched)
        return res.render("error", {
          error: "Invalid request",
          message: "Please provide correct credentials"
        });
      const authToken = jwt.sign({ id: userExist.id.toString() }, jwtSecret);
      res.cookie("rtchat_auth_token", authToken, { maxAge: 604800000 });
      res.redirect("/");
    } catch (error) {
      res.render("error", {
        error: "Server side error occurred",
        message: error
      });
    }
  }
);

router.get("/logout", async (req, res) => {
  try {
    const { userStatus } = req;
    if (!userStatus.loggedIn) return res.redirect("/not-found");
    res.clearCookie("rtchat_auth_token");
    res.redirect("/auth/login");
  } catch (error) {
    res.render("error", {
      error: "Server side error occurred",
      message: error
    });
  }
});

module.exports = router;