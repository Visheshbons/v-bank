import express from "express";
import chalk from "chalk";

import { app, port, version, checkForbiddenChars, hashPassword, verifyPassword, userLogin, User } from "./appConfig.js";

app.set("view engine", "ejs");
app.use(express.static("public"));

let userLoggedInRN = false; // Simulating user login status

app.get("/", (req, res) => {
  res.render("index", {
    version,
    userLoggedInRN,
  });
});

app.get("/register", (req, res) => {
    res.render("register", {
      version,
      userLoggedInRN,
    });
  })
  .post("/register", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
    const { username, password_sha256 } = req.body;
    console.log(`User login: username ${username}, with password_sha256 ${password_sha256}`)
    const hashedPassword = await hashPassword(password_sha256);
    new User(username, hashedPassword);
    res.redirect("/");
  }); 

app.get("/login", (req, res) => {
  res.render("login", {
    version,
    userLoggedInRN,
  });
})
  .post("/login", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
    const { username, password_sha256 } = req.body;
    if (await userLogin(username, password_sha256)) {
      res.redirect("/");
    } else {
      res.redirect("/login#error")
    }
  })

app.listen(port, () => {
  console.log(`Server is running on port ${chalk.green(port)}`);
});
