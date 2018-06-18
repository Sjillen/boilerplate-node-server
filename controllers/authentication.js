const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({
            sub: user.id,
            iat: timestamp
        },
        config.secret
    );
}

exports.signin = function(req, res, next) {
    // Users have already had their email and password auth'd
    // We just need to give them a token
    res.send(({ token: tokenForUser(req.user) }));
};

exports.signup = function(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;

    if(!email || !password) {
        return res.status(422).send('You must provide an Email and a Password');
    }
    // see if a user with a given email exists
    User.findOne({ email: email}, function(err, existingUser) {
        if(err) { return next(err); }

        // if a user with email does exists, return an error
        if(existingUser) {
            return res.status(422).send({ error: 'Email is in use' });
        }
        // if a user with email does not exists, creates and saves user record
        const user = new User({
            email: email,
            password: password
        });

        user.save(function(err) {
            if(err) { return next(err); }
        });
        // respond to request indicating the user was created
        res.json({ token: tokenForUser(user) });
    });
};