const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = { usernameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
    // Verify this email and password, call done with the user
    // if it is the correct email and password
    // otherwise, call done with false
    User.findOne({ email: email }, function(err, user) {
        if(err) { return done(err); }
        if(!user) { return done(null, false); }

        // Compare passwords - is `password` equal to user.password?
        user.comparePassword(password, function(err, isMatch) {
            if(err) { return done(err); }
            if(!isMatch) { return done(null, false); }
            return done(null, user); // passport will assign user to req.user so we can reuse it to signin
        });
    });
});

// Setup options for JWT strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if the user ID in the payload exists in our database
    // If it does call "done" with that user
    // Otherwise call "done" without the user object
    User.findById(payload.sub, function(err, user) {
        if(err) { return done(err, false); }
        if(user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
});

// Tell Passport to use this JWT strategy
passport.use(jwtLogin);
// Tell Passport to use the Local strategy
passport.use(localLogin);