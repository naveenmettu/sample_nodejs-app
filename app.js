const express = require('express');
const session = require('express-session');
const handlebars  = require('express-handlebars');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const authMiddleware = require('./middleware/auth');

const app = express();

app.engine('handlebars', handlebars({defaultLayout: 'main'}));
app.set('view engine', 'handlebars');
app.set('views', __dirname + '/views')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    name: 'att-dp-sso-user',
    saveUninitialized: true
  })
);

app.use(morgan('dev', {
    skip: function (req, res) {
        return res.statusCode < 400
    }, stream: process.stderr
}));

app.use(morgan('dev', {
    skip: function (req, res) {
        return res.statusCode >= 400
    }, stream: process.stdout
}));

authMiddleware.init(app);

// Routers are bootstrapped after authMiddleware has initialized,
// So that any passport authentication bootstrappers will occur
// after passport has initialized
const router = require('./routes');

app.use('/', router);

// catch 404 and forward to error handler
app.use((req, res, next) => {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use((err, req, res, next) => {
  if (err && err.status !== 404) {
    console.error(err);
  }

  // set locals, only providing error in development
  err = req.app.get('env') === 'development' ? err : {};

  // send error to client, 500 if unspecified or uncaught
  res.status(err.status || 500);
  res.json(err);
});

module.exports = app;