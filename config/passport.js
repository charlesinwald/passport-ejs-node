const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

//Load User Model
const User = require('../models/User');

module.exports = function (passport) {
  passport.use(
    new LocalStrategy({usernameField: 'email'}, (email, password, done) => {
      //Match User (is that email registered)
      User.findOne({email: email})
        .then(user => {
          //If no user matched
          if (!user) {
            return done(null, false, {message: "That email is not registered"});
          }

          //Match password
          //password is the supplied password, user.password is the hashed password from the database
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;

            if (isMatch) {
              //Correct Password, return user
              done(null, user)
            } else {
              return done(null, false, {message: "Incorrect Password"});

            }
          });
        })
        .catch(err => console.log(err));
    })
  );
  //Session Management
  //In a typical web application, the credentials used to authenticate a user will only be transmitted during the login
  // request. If authentication succeeds, a session will be established and maintained via a cookie set in the user's browser.
  //
  // Each subsequent request will not contain credentials, but rather the unique cookie that identifies the session.
  // In order to support login sessions, Passport will serialize and deserialize user instances to and from the session.

  passport.serializeUser(function (user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });
};