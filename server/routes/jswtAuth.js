const router = require('express').Router();
const {User} = require('../models');
const bcrypt = require('bcrypt');
const validInfo = require('../middleware/validinfo');
const jwtGenerator = require('../utils/jwtGenerator');
const authorization = require('../middleware/authorization');
const login = require('../middleware/login');
const logout = require('../middleware/logout');
const jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
require("dotenv").config();

// registering consumer user
router.post("/register", validInfo, async (req, res) => {
    try {
        const user = await User.findOne({
            where: {
                email: req.body.email
            }
        });

        if (user) {
            return res.status(403).json("Email already registered");
        }

        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const newUser = User.build({
            email: req.body.email,
            password: hashedPassword,
            permissions: req.body.permissions
        });

        await newUser.save();
        return res.status(200).json("Success")
    } catch (err) {
        console.error(err.message);
        res.status(500).json("Server Error");
    }
});




// page to send out email to register restaurant
router.post("/register/restaurant_registration_email", async (req, res) => {
    try {
        
        const restaurant = await User.findOne({
            where: {
                email: req.body.email
            }
        });

        if (restaurant) {
            return res.status(401).json("Restaurant already exists");
        };

        const token = jwt.sign({email: req.body.email}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

        const link = `http://localhost:3001/register_restaurant/${token}`;
        
        var transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "crystalcoastdining@gmail.com",
                pass: "*"
            }
        });

        var mailOptions = {
            from: "crystalcoastdining@gmail.com",
            to: req.body.email,
            subject: "Restaurant Registration",
            headers: {
                "token": token
            },
            text: `Please visit ${link} to register your restaurant at Crystal Coast Curated. This link is valid for 15 minutes.`
        };
        console.log("hi")
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error.message)
            } else {
                console.log(success)
            }
        })
        
    } catch (err) {
        console.error(err.message);
        res.status(500).json("Server Error")
    }
});




// check for registration token
router.post("/register/valid_token", async (req, res) => {
    try {
        const jwtToken = req.body.token;
        const valid = jwt.verify(jwtToken, process.env.ACCESS_TOKEN_SECRET);

        if (valid) {
            return res.json(true);
        }

    } catch (err) {
        return res.json(false);
    }
});




// page for restaurant registration
router.post("/register/restaurant_registration", validInfo, async (req, res) => {
    try {
        const restaurant = await User.findOne({
            where: {
                restaurant_name: req.body.restaurant_name
            }
        });

        if (restaurant) {
            return res.status(401).json("Restaurant already exists");
        }

        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const newRestaurant = await User.build({
            restaurant_name: req.body.restaurant_name,
            email: req.body.email,
            password: hashedPassword,
            permissions: 2
        })

        await newRestaurant.save();
        return res.status(200).json("Success")
    } catch (err) {
        console.error(err.message);
    }
})




// login
router.post("/login", login, async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({
            where: {
                email: email
            }
        });

        if (!user) {
            return res.status(401).json("Password or Email is incorrect");
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json("Password or Email is incorrect");
        }

        const token = jwtGenerator(user.user_id);

        return res.json({token});

    } catch (err) {
        console.error(err.message);
        res.status(500).json("Server Error");
    }
})




// token validation
router.get("/is-verified", authorization, async (req, res) => {
    try {
        console.log(req.currentUser)
        console.log("SuCcEs");
        return res.json(req.user)
    } catch (err) {
        console.error(err.message);
        return res.status(403).json("Not authorized")
    };
});




// logout
router.delete("/logout", logout, async (req, res) => {
    try {
        console.log("SuCcEs");
        
        return res.sendStatus(204)
    } catch (err) {
        console.error(err.message);
    }
})


module.exports = router;