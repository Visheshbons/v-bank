import express from "express";
import chalk from "chalk";
import argon2 from "argon2";
import { marked } from "marked";

const app = express();
const port = 3000;
const version = "0.0.1";

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

// ==================== ARGON2 ==================== \\
async function hashPassword(password) {
  try {
    const hash = await argon2.hash(password);
    return hash;
  } catch (err) {
    console.error("Error hashing password:", err);
    throw err;
  }
}

async function verifyPassword(hash, password) {
  try {
    const isValid = await argon2.verify(hash, password);
    return isValid;
  } catch (err) {
    console.error("Error verifying password:", err);
    throw err;
  }
}

// ==================== USERS ==================== \\
let users = []; // <------------------------------------- MongoDB Implementation HERE

class User {
  constructor(username, pass) {
    this.user = username;
    this.pass = pass;

    // ID format: aaaabbbc
    // aaaa - random hex characters
    // bbb - index of user in users array, padded to 3 digits (hex)
    // c - checksum digit (hex)
    this.id = this.#generateId();
    users.push(this);

    this.loggedInRN = false;

    this.balance = 0;
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

    return randomPart + indexPart + checksum.toString(16);
  }
}

async function userLogin(username, password) {
  const user = users.find((u) => u.username === username);
  if (!user) {
    console.log(chalk.red("User not found"));
    return false;
  }

  if (user.user !== username) {
    console.log(chalk.red("Invalid username"));
    return false;
  }

  const isMatch = await verifyPassword(user.pass, password);
  if (!isMatch) {
    console.log(chalk.red("Invalid password"));
    return false;
  }

  user.login();
  return true;
}

// ==================== EXPORTS ==================== \\
export { app, port, version, User, checkForbiddenChars, hashPassword, verifyPassword, userLogin };
