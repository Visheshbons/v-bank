// logs are:
// 0 - no logs
// 1 - critical errors only
// 2 - errors and startup logs only
// 3 - most debug logs (default)
// 4 - all logs that do not contain sensitive info
// 5 - everything
let logging = process.env.LOGS || 3;

logging >= 1 && console.time("Loading time");

import express from "express";
import chalk from "chalk";
import cookieParser from "cookie-parser";

export { logging }; // for appConfig.js

import { app, port, version, checkForbiddenChars, hashPassword, verifyPassword, userLogin, User, debug, token, checkAuth, blockAuth } from "./appConfig.js";
logging >= 3 && console.timeLog("Loading time", "- appConfig.js loaded");

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cookieParser());

app.get("/", checkAuth, (req, res) => {
  const currentUser = User.find("user", req.cookies?.username);
  const userLoggedInRN = currentUser?.loggedInRN || false;

  // const error = new Error("test");
  // error.status = 500;
  // throw error; // test error page

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
}).post("/register", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
  const { username, password_sha256 } = req.body;
  const hashedPassword = await hashPassword(password_sha256);
  new User(username, hashedPassword);
  res.cookie("loggedIn", "true", { maxAge: 9000000 })
  res.cookie("username", username, { maxAge: 9000000 })
  res.cookie("token", token(username), { maxAge: 9000000 })
  res.redirect("/");
  logging >= 3 && debug()
});

app.get("/login", (req, res) => {
  res.render("login", {
    version
  });
}).post("/login", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
  const { username, password_sha256 } = req.body;
  const valid = await userLogin(username, password_sha256);
  if (valid === 0) {
    res.cookie("loggedIn", "true", { maxAge: 9000000 })
    res.cookie("username", username, { maxAge: 9000000 })
    res.cookie("token", token(username), { maxAge: 9000000 })
    res.redirect("/");
  } else {
    res.redirect(`/login?error=${valid}`); // handled in login.ejs
  }
  logging >= 3 && debug()
});

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

app.get("/account", blockAuth, (req, res) => {
  const userData = User.find("user", req.cookies.username);
  // no need for "if (!user)" bc blockAuth
  let user = {};
  let transactions = [];

  try {
    user = {
      user: userData.user,
      id: userData.id,
      balance: userData.balance,
      transactions: userData.transactions
    };
  } catch (e) {
    if (logging >= 1) {
      console.error("\n" + chalk.bgRed.yellow(`[CRITICAL ERROR]:`) + chalk.red(` Failed to retrieve user data for account page.`));
      console.error(chalk.red("======= ERROR LOG START =======\n"));
      console.error(chalk.red(`This error was thrown ${new Error().stack.split("\n")[2].trim()} in index.js while rendering /account.`));
      console.error(chalk.red(`User token: ${logging >= 5 ? req.cookies.token : chalk.grey("[SENSITIVE INFO]")}\n`));
      console.error(chalk.red(`Error details:`));
      console.error(chalk.red(logging >= 5 ? e.stack : e));
      console.error(chalk.red(`\nUser data: `));
      console.error(chalk.red(logging >= 5 ? ((userData) ? JSON.stringify(userData, null, 2) : "User data not found") : chalk.grey("[SENSITIVE INFO]")));
      console.error(chalk.red("\n======== ERROR LOG END ========\n"));
    }
    return res.redirect("/");
  }

  res.render("account", {
    version,
    user,
    transactions
  });
}).post("/transfer", blockAuth, checkForbiddenChars(["recipient", "amount"]), (req, res) => {
  const sender = User.find("user", req.cookies.username);
  const { recipient, amount } = req.body;
  const recipientUser = User.find("id", recipient);
  if (!recipientUser) {
    res.redirect("/account?error=norecipient");
    return;
  }

  sender.transfer(recipient, amount);
  res.redirect("/account?success");
});





// 404 
app.use((req, res, next) => {
  res.status(404).render("err", {
    version,
    err: {
      code: 404
    }
  })
  logging >= 2 && console.warn("\n" + chalk.bgYellow.black(`[WARNING]:`) + chalk.yellow(` 404 error - page not found. URL: ${req.url}, Method: ${req.method}`));
});

// 500(s)
app.use((err, req, res, next) => {
  if (logging >= 1) {
    console.error("\n" + chalk.bgRed.yellow(`[CRITICAL ERROR]:`) + chalk.red(` An unexpected error occurred.`));
    console.error(chalk.red("======= ERROR LOG START =======\n"));
    console.error(chalk.red(`\nError details:\n`));
    console.error(chalk.red(logging >= 5 ? (err.stack || err) : chalk.grey("Error stack may contain sensitive info, logging level needs to be at least 5 to display such info.")));
    console.error(chalk.red(`\n\nRequest details: `));
    console.error(chalk.red(`\nURL: ${req.url}`));
    console.error(chalk.red(`\nMethod: ${req.method}`));
    console.error(chalk.red(`\nHeaders: ${logging >= 5 ? JSON.stringify(req.headers, null, 2) : chalk.grey("[SENSITIVE INFO]")}`));
    console.error(chalk.red(`\nBody: ${logging >= 5 ? JSON.stringify(req.body, null, 2) : chalk.grey("[SENSITIVE INFO]")}`));
    console.error(chalk.red("\n\n======== ERROR LOG END ========\n"));
  }

  res.status(err.status || 500).render("err", {
    version,
    err: {
      code: err.status || 500
    }
  });
});

new User('admin', '$argon2id$v=19$m=65536,t=3,p=4$ieRAQoJ+M6wJm86+/vTazA$s6SyLQ745tasC0vHRQDr1le/D8qB5efBTrMeyKMt5bY', Infinity);
logging >= 3 && console.timeLog("Loading time", "- setup complete, starting server");

app.listen(port, () => {
  if (logging >= 2) {
    console.timeEnd("Loading time");
    console.log(`Server is running on port ${chalk.green(port)}`);
    console.log(`App version: ${chalk.blue(version)}`);
  };
  logging >= 3 && debug();
});
