require('dotenv').config();
const express = require('express');
const userModel = require("./models/user");
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

mongoose.connect(process.env.MONGODB_URI);

const app = express();
app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.render('index');
});

app.post("/create", (req, res) => {
  let { username, email, password, age } = req.body;

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let createdUser = await userModel.create({
        username,
        email,
        password: hash,
        age
      });

      const token = jwt.sign({ email }, process.env.JWT_SECRET);
      res.cookie("token", token);
      res.send(createdUser);
    });
  });
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render('login');
});

app.post("/login", async (req, res) => {
  const user = await userModel.findOne({ username: req.body.username });
  if (!user) return res.send("Something went wrong");

  bcrypt.compare(req.body.password, user.password, (err, result) => {
    if (result) {
      const token = jwt.sign({ username: req.body.username }, process.env.JWT_SECRET);
      res.cookie("token", token);
      res.send("Logging in");
    } else res.send("Invalid");
  });
});

app.listen(3000);
