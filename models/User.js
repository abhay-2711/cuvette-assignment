const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Please enter an email'],
        unique: true,
        maxlength: [50, 'Email cannot be more than 50 characters']
    },
    password: {
        type: String,
        required: [true, 'Please enter a password'],
    },
    
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

module.exports = User;