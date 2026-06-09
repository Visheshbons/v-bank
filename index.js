import express from 'express';
import chalk from 'chalk';

const app = express();
const port = 3000;

app.get('/', (req, res) => {
    res.send('test');
})

app.listen(port, () => {
  console.log(`Server is running on port ${chalk.green(port)}`);
});