//jshint esversion:6

//Create constants and require modules
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findOrCreate");

//Create a new app instance using express
const app = express();


app.use(express.static("public"));

//Use ejs as templating engine
app.set("view engine", "ejs");

//Use body parser to pass request
app.use(bodyParser.urlencoded({extended: true}));

//To use express-session with suggested initial config
app.use(session({
  secret: "Our little secrets.",
  resave: false,
  saveUninitialized: true,
  cookie: {}
}))

//To use Passport in an express or connect-based application, to initialize and deal with session
app.use(passport.initialize());
app.use(passport.session());

//Connect mongoose to locahost and create a new database called userDB
mongoose.connect("mongodb+srv://tiffany_chang:test123@cluster0.52l7y.mongodb.net/userDB", {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false});
mongoose.set("useCreateIndex", true);


//Create a schema in the DB
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

//To use passport-local-mongoose as a plugin for hashing and saltiing the passwords and save in our DB.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create a model in the schema
const User = new mongoose.model("User", userSchema);

// USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

//Use passport to serialize and deserialize without Google+
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


//USE passport-google-oauth20 to setup Google Strategy as passport plugin for easy access to Google Authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.CLIENT_ID_FB,
  clientSecret: process.env.CLIENT_SECRET_FB,
  callbackURL: "http://localhost:3000/auth/facebook/secrets",
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function(err, user) {
    return cb(err, user);
  });
}));


app.get("/", function(req, res) {
  res.render("home");
});

//Authenticate Requests: Google and Facebook
app.get("/auth/google",
  //use passport to authenticate our user using the Google Strategy
  passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login"}),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/auth/facebook",
  //use passport to authenticate our user using the Facebook Strategy
  passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if(err) {
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  })
});

app.get("/submit", function(req, res) {
  if(req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//Make a post request to submit a secret
app.post("/submit", function(req, res) {
  //Make a constance to the submitted secret
  const submittedSecret = req.body.secret;
  //Save secret to the login id by using mongoose findById method
  User.findById(req.user.id, function(err, foundUser) {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        //attach the secret to this user id
        foundUser.secret = submittedSecret;
        //save it and redirect to the secret page
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
    // console.log(req.user.id);
});

app.get("/logout", function(req, res) {
  req.logout(); //passport lotout method
  res.redirect("/");
});


//only render the secrets page when user is registerd or logged in
app.post("/register", function(req, res) {
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //password login method
  req.login(user, function(err) {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
