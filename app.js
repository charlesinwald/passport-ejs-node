
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const app = express();
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
//Passport config
require('./config/passport')(passport);

//Database Config
const db = require('./config/keys').MongoURI;
//Connect to MongoDB
mongoose.connect(db, { useNewUrlParser:true })
  .then(() => console.log("MongoDB connected..."))
  .catch(err => console.log(err));

//EJS
app.use(expressLayouts);
app.set('view engine', 'ejs');

//Bodyparser
app.use(express.urlencoded({ extended: false }));

//Express Session Middleware
app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
}));

//Passport Middleware
app.use(passport.initialize());
app.use(passport.session());

//Connect Flash
app.use(flash());

//Global Variables
app.use((req, res, next) => {
  res.locals.success_msg =req.flash('success_msg');
  res.locals.error_msg =req.flash('error_msg');
  next();
});

//Routes
app.use('/', require('./routes/index'));
app.use('/users', require('./routes/users'));

//port is 5000 on local host, otherwise env variable
const PORT = process.env.PORT || 5000;

app.listen(PORT, console.log(`Server started on port ${PORT}`));




