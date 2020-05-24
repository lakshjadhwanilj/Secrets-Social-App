// Requiring dotenv for environment variable file
require('dotenv').config();

// Requiring packages
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

// Mongoose default encryption
// const encrypt = require('mongoose-encryption');
// MD5 encryption
// const md5 = require('md5');
// Bcrypt encryption
// const bcrypt = require('bcrypt');

// Requiring passport.js
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

// Requiring google oauth 
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require('mongoose-findorcreate');

//const saltRounds = 10;
const app = express();

app.use(express.static('public')); // Initializing static files
app.set('view engine', 'ejs'); // Setting view engine
app.use(bodyParser.urlencoded({ // Using body parser
    extended: true
}));

// Initializing session
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}));

// Initializing passport & then making it deal with the session
app.use(passport.initialize());
app.use(passport.session());

// Connecting to mongoDB
mongoose.connect('mongodb://localhost:27017/userDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

mongoose.set('useCreateIndex', true);

// Creating mongoose schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// Adding passport local mongoose plugin
userSchema.plugin(passportLocalMongoose);
// Adding find or create plugin
userSchema.plugin(findOrCreate);

// Using default mongoose encryption plugin
/*
userSchema.plugin(encrypt, {
    secret: process.env.SECRET,
    encryptedFields: ['password']
});
*/

// Creating mongoose model
const User = new mongoose.model('User', userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

// Using the google strategy
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/secrets',
        userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

// Routing 
app.get('/', (req, res) => {
    res.render('home');
});

// Route for login via google
app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile']
    })
);

// The get route after logging via google
app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    }
);

//
app.get('/secrets', (req, res) => {
    User.find({
        'secret': {
            $ne: null
        }
    }, (err, foundUsers) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render('secrets', {
                    usersWithSecrets: foundUsers
                });
            }
        }
    });
});

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(() => {
                    res.redirect('/secrets');
                });
            }
        }
    });
})

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, err => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

// Bcrypt post route
/*
app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password;
    //const password = md5(req.body.password);

    User.findOne({
        email: username
    }, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                bcrypt.compare(password, foundUser.password, function (err, result) {
                    // result == true
                    res.render('secrets');
                });
            } else {
                res.send('No such user found please register.');
            }
        }
    })
});
*/


// Register to App
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    User.register({
            username: req.body.username
        },
        req.body.password,
        (err, user) => {
            if (err) {
                console.log(err);
                res.redirect('/register');
            } else {
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/secrets');
                });
            }
        }
    );
});

// Bcrypt post route
/*
app.post('/register', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            //password: md5(req.body.password)
            password: hash
        });
        newUser.save(err => {
            if (err) {
                console.log(err);
            } else {
                res.render('secrets');
            }
        });
    });
});
*/

// Logout route
app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

app.listen(3000, () =>
    console.log('Server started at port 3000.')
);