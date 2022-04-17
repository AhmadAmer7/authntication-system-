const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const resetToken = require('../model/resetTokens');
const user = require('../model/user');
const mailer = require('./sendMail');
const bcryptjs = require('bcryptjs');
const passport=require('passport');
require('./passportLocal')(passport);
require('./googleAuth')(passport);
const userRoutes = require('./accountRoutes');



function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        next();
    } else {
        req.flash('error_messages', "Please Login to continue !");
        res.redirect('/login');
    }
}



router.get('/', (req, res) => {
   
    if (req.isAuthenticated()) {
        res.render("index", { logged: true });
    } else {
        res.render("index", { logged: false });
    }
});

router.get('/login', (req, res) => {
    res.render("login", { csrfToken: req.csrfToken() }); 
   
});

router.get('/signup', (req, res) => {
    res.render("signup", { csrfToken: req.csrfToken() });
});

router.post('/signup', (req, res) => {
    // get all the values 
    const { email, username, password, confirmpassword } = req.body;
    // check if the are empty 
    if (!email || !username || !password || !confirmpassword) {
        res.render("signup", { err: "All Fields Required !", csrfToken: req.csrfToken() });
    } else if (password != confirmpassword) {
        res.render("signup", { err: "Password Don't Match !", csrfToken: req.csrfToken() });
    } else {

        // validate email and username and password 
        // skipping validation
        // check if a user exists
        user.findOne({ $or: [{ email: email }, { username: username }] }, function (err, data) {
            if (err) throw err;
            if (data) {
                res.render("signup", { err: "User Exists, Try Logging In !", csrfToken: req.csrfToken() });
            } else {
                // generate a salt
                bcryptjs.genSalt(12, (err, salt) => {
                    if (err) throw err;
                    // hash the password
                    bcryptjs.hash(password, salt, (err, hash) => {
                        if (err) throw err;
                        // save user in db
                        user({
                            username: username,
                            email: email,
                            password: hash,
                            googleId: null,
                            provider: 'email',
                        }).save((err, data) => {
                            if (err) throw err;
                            // login the user
                            // use req.login
                            // redirect , if you don't want to login
                            res.redirect('/login');
                        });
                    })
                });
            }
        });
    }
});

// adding the checkAuth middleware to make sure that 
// only authenticated users can send emails
router.get('/user/send-verification-email',  async (req, res) => {
    // check if user is google or already verified
    if (req.user.isVerified || req.user.provider == 'google') {
        // already verified or google user
        // since we won't show any such option in the UI 
        // most probably this is being called by mistake or can be an attack
        // simply redirect to profile 
        res.redirect('/profile');
    } else {
        // generate a token 
        var token = crypto.randomBytes(32).toString('hex');
        // add that to database
        await resetToken({ token: token, email: req.user.email }).save();
        // send an email for verification
        mailer.sendVerifyEmail(req.user.email, token);
        res.render('profile', { username: req.user.username, verified: req.user.isVerified, emailsent: true });
    }
});


router.get('/user/verifyemail', async (req, res) => {
    // grab the token
    const token = req.query.token;
    // check if token exists 
    // or just send an error
    if (token) {
        var check = await resetToken.findOne({ token: token });
        if (check) {
            // token verified
            // set the property of verified to true for the user
            var userData = await user.findOne({ email: check.email });
            userData.isVerified = true;
            await userData.save();
            // delete the token now itself
            await resetToken.findOneAndDelete({ token: token });
            res.redirect('/profile');
        } else {
            res.render('profile', { username: req.user.username, verified: req.user.isVerified, err: "Invalid token or Token has expired, Try again." });
        }
    } else {
        // doesnt have a token
        // I will simply redirect to profile 
        res.redirect('/profile');
    }
});

router.post('/login', (req, res, next) => {
  
    passport.authenticate('local', {
        failureRedirect: '/login',
        successRedirect: '/profile',
        failureFlash: true,
    })(req, res, next);
     
});
  router.get('/login'),(req,res,next)=>{
    res.cookie('name', 'express').send('cookie set'); //Sets name = express
  }
router.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy(function (err) {
        res.redirect('/');
    });
});
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email',] }));

router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/profile');
});

router.get('/profile', checkAuth, (req, res) => {
    // adding a new parameter for checking verification
    res.render('profile', { username: req.user.username, verified : req.user.isVerified });

});

router.use(userRoutes);
module.exports = router;