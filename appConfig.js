import express from "express";
import chalk from "chalk";
import argon2 from "argon2";
import { marked } from "marked";
import fs from "fs";
// import { logging } from "./index.js";

const packageData = JSON.parse(fs.readFileSync("./package.json", "utf-8"));
const version = packageData.version;

const app = express();
const port = 3000;
const DEV = true;

// logs are:
// 0 - no logs
// 1 - critical errors only
// 2 - errors and startup logs only
// 3 - most debug logs (default)
// 4 - all logs that do not contain sensitive info
// 5 - everything
import dotenv from "dotenv";
dotenv.config();
const logging = Number.parseInt(process.env.LOGS ?? "3", 10) || 3

// ==================== MIDDLEWARE ==================== \\
app.use(express.urlencoded({ extended: true })); // For parsing form data
app.set("view engine", "ejs");
app.use(express.static("public"));

marked.setOptions({
  highlight: function (code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    } else {
      return hljs.highlightAuto(code).value;
    }
  },
});

const forbiddenChars = /[\/\\{}\[\]<>\"']/;

function checkForbiddenChars(fields) {
  return (req, res, next) => {
    for (const field of fields) {
      if (req.body[field] && forbiddenChars.test(req.body[field])) {
        if (logging >= 4) {
          console.warn(chalk.bgYellow.black("[WARNING]:") + chalk.yellow(` Input containing forbidden characters in field: ${field}. Value: ${logging >= 5 ? req.body[field] : chalk.grey("[SENSITIVE INFO]")}`));
        }
        return res.status(400).send(`
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <title>Input Error</title>
                    </head>
                    <body>
                        <center><pre>
                        Input contains illegal characters: / \\ { } [ ] < > " ' <br>
                        You are an idiot. <br>
                        Eres un idiota. <br>
                        Vous êtes un idiot. <br>
                        你是个白痴。 <br>
                        君はバカだ。 <br>
                        Tu es un imbécile. <br>
                        Du bist ein Idiot. <br>
                        Você é um idiota. <br>
                        </pre></center>
                    </body>
                    </html>
                `);
      }
    }
    next();
  };
}

function checkAuth(req, res, next) {
  const loggedIn = req.cookies.loggedIn;
  if (!loggedIn) {
    res.cookie("loggedIn", "false")
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` No loggedIn cookie present, fixing cookies to match state.`))
    return next();
  }

  const user = User.find("user", req.cookies?.username);
  if (!user) {
    res.cookie("loggedIn", "false")
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` No user found matching username cookie, fixing cookies to match state. Username cookie value: ${logging >= 5 ? req.cookies?.username : chalk.grey("[SENSITIVE INFO]")}`))
    return next();
  }

  const token = req.cookies?.token;
  if (user.token === token) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` User authenticated successfully with token. Username: ${logging >= 5 ? user.user : chalk.grey("[SENSITIVE INFO]")}`))
    return next();
  } else {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Invalid token for user. Fixing cookies to match state. Username: ${logging >= 5 ? user.user : chalk.grey("[SENSITIVE INFO]")}, Token cookie value: ${logging >= 5 ? token : chalk.grey("[SENSITIVE INFO]")}`))
    res.cookie("loggedIn", "false")
    res.clearCookie("token");
    res.clearCookie("username");
    return next();
  }
}

// checkAuth but better :D
function blockAuth(req, res, next) {
  const loggedIn = req.cookies.loggedIn;
  if (!loggedIn) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` No loggedIn cookie present, redirecting to login. URL: ${req.originalUrl}`))
    res.cookie("loggedIn", "false")
    return res.redirect("/login");
  }

  const user = User.find("user", req.cookies?.username);
  if (!user) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` No user found matching username cookie, redirecting to login. Username cookie value: ${logging >= 5 ? req.cookies?.username : chalk.grey("[SENSITIVE INFO]")}, URL: ${req.originalUrl}`))
    res.cookie("loggedIn", "false")
    return res.redirect("/login");
  }

  const token = req.cookies?.token;
  if (user.token === token) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` User authenticated successfully with token, allowing access to protected route. Username: ${logging >= 5 ? user.user : chalk.grey("[SENSITIVE INFO]")}, URL: ${req.originalUrl}`))
    return next();
  } else {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Invalid token for user, redirecting to login. Username: ${logging >= 5 ? user.user : chalk.grey("[SENSITIVE INFO]")}, Token cookie value: ${logging >= 5 ? token : chalk.grey("[SENSITIVE INFO]")}, URL: ${req.originalUrl}`))
    res.cookie("loggedIn", "false")
    res.clearCookie("token");
    res.clearCookie("username");
    return res.redirect("/login");
  }
}

// ==================== ARGON2 ==================== \\
async function hashPassword(password) {
  try {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Hashing password.`))
    logging >= 5 && console.time("Password hashed in");
    const hash = await argon2.hash(password);
    logging >= 5 && console.timeEnd("Password hashed in");
    return hash;
  } catch (err) {
    // logging >= 2 && console.error("Error hashing password:", err);
    if (logging >= 2) {
      console.error(chalk.red("======= ERROR LOG START ======="));
      console.error(chalk.red(`This error was thrown ${err.stack.split("\n")[1].trim()} in appConfig.js.`));
      console.error(chalk.red("Error hashing password:"));
      console.error(chalk.red(err));
      console.error(chalk.red("======== ERROR LOG END ========\n"));
    }
    throw err;
  }
}

async function verifyPassword(hash, password) {
  try {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Verifying password.`));
    logging >= 5 && console.time("Password verified in");
    const isValid = await argon2.verify(hash, password);
    logging >= 5 && console.timeEnd("Password verified in");
    return isValid;
  } catch (err) {
    if (logging >= 2) {
      console.error(chalk.red("======= ERROR LOG START ======="));
      console.error(chalk.red(`This error was thrown ${err.stack.split("\n")[1].trim()} in appConfig.js.`));
      console.error(chalk.red("Error verifying password:"));
      console.error(chalk.red(err));
      console.error(chalk.red("======== ERROR LOG END ========\n"));
    }
    throw err;
  }
}

// ==================== USERS ==================== \\
let users = []; // <------------------------------------- MongoDB Implementation HERE

class User {
  constructor(username, pass, balance = 0) {
    this.user = username;
    this.pass = pass;

    // ID format: aaaabbbc
    // aaaa - random hex characters
    // bbb - index of user in users array, padded to 3 digits (hex)
    // c - checksum digit (hex)
    this.id = this.#generateId();
    users.push(this);

    this.loggedInRN = true; // account just created

    this.balance = balance;
    if (balance > 0) {
      this.loggedInRN = false; // bc must be preset :D
    }
    this.transactions = [];

    this.token = ""; // user access token for auth
  }

  login() {
    this.loggedInRN = true;
  }

  logout() {
    this.loggedInRN = false;
  }

  #generateId() {
    // 4 random hex chars
    const randomPart = Math.random().toString(16).substring(2, 6);

    // index in hex, padded to 3 chars
    const indexPart = users.length.toString(16).padStart(3, "0");

    // simple checksum
    const checksum =
      (randomPart.split("").reduce((sum, char) => sum + parseInt(char, 16), 0) +
        parseInt(indexPart, 16)) %
      16;

    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Generated user ID: ${randomPart + indexPart + checksum.toString(16)}`))
    return randomPart + indexPart + checksum.toString(16);
  }

  // for index.js
  static find(type, value) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Searching for user with ${type}: ${logging >= 5 ? value : chalk.grey("[SENSITIVE INFO]")}`))
    if (value === undefined || value === null || value === "") {
      return null;
    }
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Users found.`))
    return users.find((u) => u[type] === value);
  }

  transfer(recipient_id, amount) {
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Initiating transfer from user ID ${logging >= 5 ? this.id : chalk.grey("[SENSITIVE INFO]")} to recipient ID ${logging >= 5 ? recipient_id : chalk.grey("[SENSITIVE INFO]")} for amount ${logging >= 5 ? amount : chalk.grey("[SENSITIVE INFO]")}`))
    logging >= 5 && console.time("Transfer completed in");
    let recipient = users.find((u) => u.id === recipient_id);
    if (!recipient) {
      // recipient not found
      logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Recipient not found for transfer. Recipient ID: ${logging >= 5 ? recipient_id : chalk.grey("[SENSITIVE INFO]")}`))
      logging >= 5 && console.timeEnd("Transfer completed in");
      return;
    }

    new Transaction(this.id, recipient_id, amount);
    logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Transfer complete. Sender balance: ${logging >= 5 ? this.balance : chalk.grey("[SENSITIVE INFO]")}, Recipient balance: ${logging >= 5 ? recipient.balance : chalk.grey("[SENSITIVE INFO]")}`))
    logging >= 5 && console.timeEnd("Transfer completed in");
  }
}

async function userLogin(username, password) {
  const user = users.find((u) => u.user === username);
  if (!user) {
    // logging >= 2 && console.log(chalk.red("User not found"));
    if (logging >= 2) {
      console.warn(chalk.bgYellow.black("[WARNING]:") + chalk.yellow(` User not found during login attempt for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`));
    }
    return 1; // handled in index.js
  }

  // if (user.user !== username) {
  //   console.log(chalk.red("Invalid username"));
  //   return false;
  // }

  const isMatch = await verifyPassword(user.pass, password);
  if (!isMatch) {
    if (logging >= 2) {
      console.warn(chalk.bgYellow.black("[WARNING]:") + chalk.yellow(` Invalid password for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`));
    }
    return 2; // handled again in index.js
  }

  user.login();
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` User logged in successfully. Username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`))
  return 0; // success
}

// dont ask but i just had to use a class :D
//   - Vishesh Kudva, 2026
class Transaction {
  constructor(senderId, recipientId, amount) {
    // IDs MUST be validated beforehand
    this.senderId = senderId;
    this.recipientId = recipientId;
    this.amount = amount;
    this.timestamp = new Date();

    this.#run();
  }

  #run() {
    const sender = users.find((u) => u.id === this.senderId);
    const recipient = users.find((u) => u.id === this.recipientId);

    if (!sender || !recipient) {
      // big oof
      if (logging >= 1) {
        console.error("\n" + chalk.bgRed.yellow(`[CRITICAL ERROR]:`) + chalk.red(` Sender or recipient not found.`));
        console.error(chalk.red("======= ERROR LOG START ======="));
        console.error(chalk.red(`This error was thrown ${new Error().stack.split("\n")[2].trim()} in appConfig.js.`));
        console.error(chalk.red(`Sender ID: ${logging >= 5 ? this.senderId : chalk.grey("[SENSITIVE INFO]")}`));
        console.error(chalk.red(`Recipient ID: ${logging >= 5 ? this.recipientId : chalk.grey("[SENSITIVE INFO]")}`));
        console.error(chalk.red("======== ERROR LOG END ========\n"));
      }
      return false;
    }

    if (sender.balance < this.amount) {
      return false;
    }

    sender.balance -= this.amount;
    recipient.balance += this.amount;

    sender.transactions.push(this);
    recipient.transactions.push(this);

    return true;
  }
}

// ==================== MISC ==================== \\
function debug() {
  if (!DEV) return;
  console.log(chalk.yellow("\n========== DEBUG INFO START =========="));
  console.log(chalk.yellow("User Array"))
  if (logging < 5) {
    // cannot show id, balance, token, or username
    // can show transactions but need to clean
    console.log(users.map(u => ({
      pass: u.pass,
      loggedInRN: u.loggedInRN,
      transactions: u.transactions.map(t => ({
        senderId: "hidden",
        recipientId: "hidden",
        amount: t.amount,
        timestamp: t.timestamp
      }))
    })));
  } else {
    console.log(users);
  }
  console.log(chalk.yellow("=========== DEBUG INFO END ===========\n"));
}

function token(username) {
  logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` Generating token for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`));
  logging >= 5 && console.time("Token generated in");
  const user = users.find((u) => u.user === username);
  if (!user) {
    logging >= 2 &&console.warn(chalk.bgYellow.black("[WARNING]:") + chalk.yellow(` User not found during token generation for username: ${logging >= 5 ? username : chalk.grey("[SENSITIVE INFO]")}`));
    logging >= 5 && console.timeEnd("Token generated in");
    return false;
  }
  // Random 32 char string
  user.token = Math.random().toString(16).substring(2, 34);
  logging >= 5 && console.timeEnd("Token generated in");
  return user.token;
}

// ==================== EXPORTS ==================== \\
export { app, port, version, User, checkForbiddenChars, hashPassword, verifyPassword, userLogin, debug, token, checkAuth, blockAuth };
logging >= 5 && console.log(chalk.blue("[INFO]:") + chalk.grey(` app.Config fully loaded. Version: ${version}`))