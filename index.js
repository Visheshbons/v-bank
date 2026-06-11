import express from "express";
import chalk from "chalk";
import cookieParser from "cookie-parser";

import { app, port, version, checkForbiddenChars, hashPassword, verifyPassword, userLogin, User, debug, token, checkAuth } from "./appConfig.js";

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cookieParser());

app.get("/", checkAuth, (req, res) => {
  const currentUser = User.find("user", req.cookies?.username);
  const userLoggedInRN = currentUser?.loggedInRN || false;

  res.render("index", {
    version,
    userLoggedInRN,
    balance: currentUser?.balance || 0,
  });
});

app.get("/register", (req, res) => {
    res.render("register", {
      version
    });
  })
  .post("/register", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
    const { username, password_sha256 } = req.body;
    const hashedPassword = await hashPassword(password_sha256);
    new User(username, hashedPassword);
    res.cookie("loggedIn", "true", { maxAge: 9000000 })
    res.cookie("username", username, { maxAge: 9000000 })
    res.cookie("token", token(username), { maxAge: 9000000 })
    res.redirect("/");
    debug()
  }); 

app.get("/login", (req, res) => {
  res.render("login", {
    version
  });
})
  .post("/login", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
    const { username, password_sha256 } = req.body;
    const valid = await userLogin(username, password_sha256);
    if (valid === 0) {
      res.cookie("loggedIn", "true", { maxAge: 9000000 })
      res.cookie("username", username, { maxAge: 9000000 })
      res.cookie("token", token(username), { maxAge: 9000000 })
      res.redirect("/");
    } else {
      res.redirect(`/login#error=${valid}`); // handled in login.ejs
    }
    debug()
  })

app.get("/logout", (req, res) => {
  // keeping cookies until after backend logic
  const user = User.find("token", req.cookies.token);
  if (user) {
    user.loggedInRN = false;
    user.token = "";
  };
  // now clear cookies
  res.clearCookie("token");
  res.clearCookie("username");
  res.cookie("loggedIn", "false")
  res.redirect("/");
});

new User('admin', '$argon2id$v=19$m=65536,t=3,p=4$ieRAQoJ+M6wJm86+/vTazA$s6SyLQ745tasC0vHRQDr1le/D8qB5efBTrMeyKMt5bY', Infinity);

app.listen(port, () => {
  console.log(`Server is running on port ${chalk.green(port)}`);
  console.log(`App version: ${chalk.blue(version)}`);
  debug();
});
