console.time("Loading time");

// logs are:
// 0 - no logs
// 1 - critical errors only
// 2 - errors and startup logs only
// 3 - most debug logs (default)
// 4 - all logs that do not contain sensitive info
// 5 - everything
import dotenv from "dotenv";
dotenv.config();
if (await process.env.ENVIRONMENT !== "development" && await process.env.LOGS == 5) {
  console.error(chalk.bgRed.yellow(`The server cannot run outside of development mode with maximum logging.`));
  // kill the server
  process.exit(1);
}
const logging = Number.parseInt(process.env.LOGS ?? "3", 10) || 3


logging >= 1 && console.timeLog("Loading time", "- environment variables loaded");

import express from "express";
import chalk from "chalk";
import cookieParser from "cookie-parser";

// .env file exists :D
// export { logging }; // for appConfig.js

import { app, port, version, checkForbiddenChars, hashPassword, verifyPassword, userLogin, User, debug, token, checkAuth, blockAuth } from "./appConfig.js";
logging >= 3 && console.timeLog("Loading time", "- appConfig.js loaded");

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(cookieParser());

app.get("/", checkAuth, (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Rendering homepage for user: ${logging >= 5 ? req.cookies.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Homepage rendered in");
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
  logging >= 5 && console.timeEnd("Homepage rendered in");
});

app.get("/register", (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Rendering registration page.`));
  logging >= 5 && console.time("Registration page rendered in");
  res.render("register", {
    version
  });
  logging >= 5 && console.timeEnd("Registration page rendered in");
}).post("/register", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Processing registration for username: ${logging >= 5 ? req.body.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Registration processed in");
  const { username, password_sha256 } = req.body;
  const hashedPassword = await hashPassword(password_sha256);
  new User(username, hashedPassword);
  res.cookie("loggedIn", "true", { maxAge: 9000000 })
  res.cookie("username", username, { maxAge: 9000000 })
  res.cookie("token", token(username), { maxAge: 9000000 })
  res.redirect("/");
  logging >= 5 && console.timeEnd("Registration processed in");
  logging >= 3 && debug()
});

app.get("/login", (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Rendering login page.`));
  logging >= 5 && console.time("Login page rendered in");
  res.render("login", {
    version
  });
  logging >= 5 && console.timeEnd("Login page rendered in");
}).post("/login", checkForbiddenChars(["username", "password_sha256"]), async (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Processing login for username: ${logging >= 5 ? req.body.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Login processed in");
  const { username, password_sha256 } = req.body;
  const valid = await userLogin(username, password_sha256);
  if (valid === 0) {
    res.cookie("loggedIn", "true", { maxAge: 9000000 })
    res.cookie("username", username, { maxAge: 9000000 })
    res.cookie("token", token(username), { maxAge: 9000000 })
    res.redirect("/");
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Login successful for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`));
  } else {
    res.redirect(`/login?error=${valid}`); // handled in login.ejs
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Login failed for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}, error code: ${valid}`));
  }
  logging >= 5 && console.timeEnd("Login processed in");
  logging >= 3 && debug()
});

app.get("/logout", (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Processing logout for user: ${logging >= 5 ? req.cookies.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Logout processed in");
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
  logging >= 5 && console.timeEnd("Logout processed in");
});

app.get("/account", blockAuth, (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Rendering account page for user: ${logging >= 5 ? req.cookies.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Account page rendered in");
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
    logging >= 5 && console.timeEnd("Account page rendered in");
    return res.redirect("/");
  }

  res.render("account", {
    version,
    user,
    transactions
  });
  logging >= 5 && console.timeEnd("Account page rendered in");
}).post("/transfer", blockAuth, checkForbiddenChars(["recipient", "amount"]), (req, res) => {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Processing transfer for user: ${logging >= 5 ? req.cookies.username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Transfer processed in");
  const sender = User.find("user", req.cookies.username);
  const { recipient, amount } = req.body;
  const recipientUser = User.find("id", recipient);
  if (!recipientUser) {
    res.redirect("/account?error=norecipient");
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Transfer failed - recipient not found. Recipient ID: ${logging >= 5 ? recipient : chalk.grey("[SENSITIVE INFO]")}`));
    logging >= 5 && console.timeEnd("Transfer processed in");
    return;
  }

  sender.transfer(recipient, amount);
  res.redirect("/account?success");
  logging >= 5 && console.timeEnd("Transfer processed in");
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
app.listen(port, () => {
  if (logging >= 2) {
    console.timeEnd("Loading time");
    console.log(`Server will log at level ${chalk.green(logging)} or higher.`);
    logging >= 5 && console.log(`You are at the ${chalk.red(`MAXIMUM LOGGING LEVEL`)}. Literaly ${chalk.red(`EVERYTHING`)} will be logged.`)
    logging >= 5 && console.log(chalk.bgRed.yellow(`Stop the server and update ".env" if this is not absolutely required.`));
    console.log(`Server is running on port ${chalk.green(port)}`);
    console.log(`App version: ${chalk.blue(version)}`);
  } else {
    console.timeEnd("Loading time");
    console.log(`V-Bank is live!`);
  }
  logging >= 3 && debug();
});

logging >= 3 && console.timeLog("Loading time", "- setup complete, starting server");
logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` index.js fully loaded. Version: ${version}`))
