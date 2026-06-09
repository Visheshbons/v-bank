import express from 'express';
import chalk from 'chalk';

const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.use(express.static('public'));


let userLoggedInRN = true; // Simulating user login status

app.get('/', (req, res) => {
    res.render('index', {
        version: '0.0.1',
        userLoggedInRN
    });
})

app.listen(port, () => {
  console.log(`Server is running on port ${chalk.green(port)}`);
});