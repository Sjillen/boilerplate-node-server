const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define the model
const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true // turn the string to lowercase before saving it
    },
    password: String
});

// On save hook, encrypt password
userSchema.pre('save', function(next) {
    //get access to user Model from context
    const user= this;
    //generate a salt then run callback
    bcrypt.genSalt(10, function(err, salt) {
       if(err) { return next(err); }
       //hash our password using this salt
       bcrypt.hash(user.password, salt, null, function(err, hash) {
            if(err) { return next(err); }
            //override plain text password with encrypted password
            user.password = hash;
            next();
       });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
       if(err) { return callback(err); }
       callback(null, isMatch);
    });
};

// Create the model class
const ModelClass = mongoose.model('user', userSchema);

// Export the model
module.exports = ModelClass;