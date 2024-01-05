require('dotenv').config();
const express = require("express");
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
//const MongoStore = require("connect-mongo");
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require("mongoose-findorcreate");
const LocalStrategy = require("passport-local").Strategy;
const cors = require('cors');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongoose').Types;
//const jwtSecret = process.env.JWT_SECRET || 'your_default_secret';
//const crypto = require("crypto");

//const clientid = ""
//const clientSecret = ""

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    //methods: ["GET", "POST"], //PUT, DELETE,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(cookieParser())

app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'YourSecretKey',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
    }
}));

//app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

const db = mongoose.connect("mongodb://127.0.0.1:27017/mydb", { useNewUrlParser: true });
db.then(() => {
    console.log("db connected....");
}).catch(err => console.error('MongoDb connection error:', err));

const varifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json("Token is missing")
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.json("Error with token")
            } else {
                if (decoded.role === "admin") {
                    next()
                } else {
                    return res.json("not admin")
                }
            }
        })
    }
}

const userSchema = new mongoose.Schema({
    username: String,
    name: String,
    password: String,
    googleId: String,
    displayName: String,
    //email: String,
    secret: String,
    role: {
        type: String,
        default: "visitor"
    },
    userdata: String,
}, { timestamps: true });

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("user", userSchema);
userSchema.plugin(findOrCreate);
module.exports = User;

passport.use(new LocalStrategy(
    function(username, password, done) {
        // Replace the following logic with your actual authentication logic
        if (username === 'user' && password === 'password') {
            return done(null, { id: 1, username: 'user' });
        } else {
            return done(null, false, { message: 'Invalid username or password' });
        }
    }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    // Replace this with your logic to fetch a user from the database by ID
    const user = { id: 1, username: 'user' };
    done(null, user);
});

//passport.use(new LocalStrategy(User.authenticate()));
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', (req, res) => {
    return res.send('Hello world')
});

app.get('/secret', varifyUser, (req, res) => {
    res.json("Success")
})

/*passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});*/
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((user, done) => {
    done(null, user);
})

//google
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID, //GOOGLE_CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET, //GOOGLE_CLIENT_SECRET,
        //callbackURL: "http://localhost:3000/auth/google/server",
        callbackURL: "/auth/google/server",
        scope: ["profile", "email"]
    },
    async(accessToken, refreshToken, profile, done) => {
        console.log("profile", profile)
        try {
            let user = await User.findOne({ googleId: profile.id });

            if (!user) {
                const username = profile.emails[0].value;

                // Check if the username already exists
                const existingUser = await User.findOne({ username });

                if (existingUser) {
                    return done(null, existingUser);
                }
                user = new User({
                    googleId: profile.id,
                    displayName: profile.displayName,
                    //email: profile.emails[0].value,
                    username: username,
                    //image: profile.photos[0].value

                });

                await user.save();
            }

            return done(null, user)
        } catch (error) {
            return done(error, null)
        }
    }
));

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile", "email"] }));

app.get("/auth/google/server", passport.authenticate("google", {
    successRedirect: "http://localhost:3000/secret",
    failureRedirect: "http://localhost:3000/login"
}))

app.post('/signup', async(req, res) => {
    try {
        const { name, username, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username is already registered. Please choose another Username.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the user
        const newUser = await User.create({ name, username, password: hashedPassword });

        res.json({ status: 'Success', user: newUser });
        /*} catch (error) {
            console.error('Error during signup:', error);
            res.status(500).json({ error: 'Internal server error' });
        }*/
    } catch (error) {
        if (error.name === 'MongoServerError' && error.code === 11000) {
            // Duplicate key error (username already exists)
            return res.status(400).json({ error: 'Username is already registered. Please choose another Username.' });
        }

        console.error('Error during signup:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username: username })
        .then(user => {
            if (!user) {
                return res.status(401).json("Invalid Email id.");
            }

            bcrypt.compare(password, user.password, (err, response) => {
                if (err) {
                    console.error('Error comparing passwords:', err);
                    return res.status(500).json("An unexpected error occurred");
                }
                if (response) {
                    const token = jwt.sign({ username: user.username, role: user.role },
                        "jwt-secret-key", { expiresIn: '1d' });
                    res.cookie('token', token, {
                        httpOnly: true,
                        sameSite: 'strict',
                    });
                    return res.json({ Status: "Success", role: user.role });
                } else {
                    return res.status(401).json("Invalid password");
                }
            });
        })
        .catch(error => {
            console.error('Error finding user:', error);
            res.status(500).json("An unexpected error occurred");
        });
});


app.get("/logout", (req, res) => {
    req.logout();
    res.json({ success: true, message: "Logged out successfully" });
});

// Add this route to your Express app
app.get('/user/:id', async(req, res) => {
    const userId = req.params.id;
    console.log('Fetching user data for userId:', userId);

    if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const user = await User.findById(userId);
        console.log('Fetched user data:', user);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // You can customize the response based on your needs
        res.json({ username: user.username || '', role: user.role });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Listening on port ${port}`));




app.post('/forgot-password', (req, res) => {
    const { username } = req.body;
    User.findOne({ username: username })
        .then(user => {
            if (!user) {
                return res.send({ Status: "User not existed" })
            }
            const token = jwt.sign({ id: user._id }, "jwt_secret_key", { expiresIn: "1d" })
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'username',
                    pass: 'password'
                }
            });

            var mailOptions = {
                from: 'youremail@gmail.com',
                to: 'myfriend@yahoo.com',
                subject: 'Reset Password Link',
                text: `http://localhost:3000/reset-password/${user._id}/${token}`
            };

            transporter.sendMail(mailOptions, function(error, info) {
                if (error) {
                    console.log(error);
                } else {
                    return res.send({ Status: "Success" })
                }
            });
        })
})

app.get("/reset-password/:id/:token", (req, res) => {
    const { id, token } = req.params
    const { password } = req.body

    jwt.verify(token, "jwt_secret_key", (err, decoded) => {
        if (err) {
            return res.json({ Status: "Error with token" })
        } else {
            bcrypt.hash(password, 10)
                .then(hash => {
                    User.findByIdAndUpdate({ _id: id }, { password: hash })
                        .then(u => res.send({ Status: "Success" }))
                        .catch(err => res.send({ Status: err }))
                })
                .catch(err => res.send({ Status: err }))
        }
    });
});