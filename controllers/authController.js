const User = require('../models/User');
const bcryptjs = require('bcryptjs');
const errorHandler = require('../utils/error');
const jwt = require('jsonwebtoken');
const nodemon = require('nodemon');

const signup = async (req, res, next) => {
    const { email, password} = req.body;
    const hashedPassword = bcryptjs.hashSync(password, 10);
    const newUser = new User({email, password: hashedPassword});
    try {
        await newUser.save();
        res.status(201).json({ message: "User Created Successfully!" });
    } catch (error) {
        next(error);
    }
}

const signin = async (req, res, next) => {
    const {email, password} = req.body;
    console.log(email, password);
    try {
        const validUser = await User.findOne({ email });
        if(!validUser) return next(errorHandler(404,"User not found"));
        const validPassword = bcryptjs.compareSync(password, validUser.password);
        if(!validPassword) return next(errorHandler(401, "Invalid Credentials"));
        const token = jwt.sign({ id : validUser._id }, process.env.JWT_SECRET);
        console.log(token);
        const { password: hashedPassword, ...rest } = validUser._doc;
        const expiryDate = new Date(Date.now() + 60*60*1000); //1 hour
        res.cookie('access_token', token, { httpOnly: true, expires: expiryDate, sameSite: 'none', secure: true } ).status(200).json(rest);
    } catch (error) {
        next(error);
    }
}

const signout  = (req, res) => {
    res.clearCookie('access_token').status(200).json('Signout success!');
}
    
module.exports = {signup, signin, signout};