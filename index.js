import express from 'express';
import chalk from 'chalk';

import { app, port, version } from './appConfig.js';

app.set('view engine', 'ejs');
app.use(express.static('public'));


let userLoggedInRN = true; // Simulating user login status

app.get('/', (req, res) => {
    res.render('index', {
        version,
        userLoggedInRN
    });
})

app.listen(port, () => {
  console.log(`Server is running on port ${chalk.green(port)}`);
});