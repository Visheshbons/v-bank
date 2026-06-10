import express from 'express';
import chalk from 'chalk';
import argon2 from 'argon2';

const app = express();
const port = 3000;
const version = '0.0.1';

// ==================== ARGON2 ==================== \\
async function hashPassword(password) {
    try {
        const hash = await argon2.hash(password);
        return hash;
    } catch (err) {
        console.error('Error hashing password:', err);
        throw err;
    }
}

async function verifyPassword(hash, password) {
    try {
        const isValid = await argon2.verify(hash, password);
        return isValid;
    } catch (err) {
        console.error('Error verifying password:', err);
        throw err;
    }
}

// ==================== USERS ==================== \\
let users = []; // <------------------------------------- MongoDB Implementation HERE

class User {
    constructor( username, pass ) {
        this.user = username;
        this.pass = pass;

        this.id = users.length + 1;
        users.push(this);

        this.loggedInRN = false;
    }

    login() {
        this.loggedInRN = true;
    }

    logout() {
        this.loggedInRN = false;
    }
}

async function userLogin(username, password) {
    const user = users.find(u => u.user === username);
    if (!user) {
        console.log(chalk.red('User not found'));
        return false;
    }

    const isMatch = await verifyPassword(user.pass, password);
    if (!isMatch) {
        console.log(chalk.red('Invalid password'));
        return false;
    }

    user.login();
    return true;
}

export { app, port, version, User };