const app = require('express')();
const dbConnect = require('./Config/db');
const bodyParser = require('body-parser');

app.set('view engine', 'ejs');

app.use(bodyParser.json());

dbConnect().then(() => {
  console.log('Connected to the database');

  app.use('/user', require('./Routes/handleUser'));

  app.get('/', (req, res) => {
    res.send('Hello World!');
  });
  app.get('/error', (req, res) => {
    throw new Error('This is an error');
  });

  app.use(function errorHandler(err, req, res, next) {
    if (res.headersSent) {
      return next(err);
    }
    res.status(500).render('error', { error: err }); // Send error response here
  });
  app.listen(3000, () => {
    console.log('Server is running on port 3000');
  });
});
