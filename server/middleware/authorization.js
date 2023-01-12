const jwt = require('jsonwebtoken');
require('dotenv').config();
const {Token, User} = require('../models');
const jwtGenerator = require('../utils/jwtGenerator');
const app = require('../server')

module.exports = async (req, res, next) => {

    try {
        const jwtToken = req.header("token");
        const load = jwt.verify(jwtToken, process.env.ACCESS_TOKEN_SECRET, {ignoreExpiration: true})

        // const refreshToken = req.header("onlyRefreshToken")

        const storedToken = await Token.findOne({
            where: {
                user_id: load.user
            }
        });

        const currentUser = await User.findOne({
            where: {
                user_id: load.user
            }
        })

        jwt.verify(jwtToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) {

                try {

                    if (!storedToken) {
                        return res.status(403).json("Not authorized");
                    }

                    const token = jwtGenerator(storedToken.user_id);
                
                    req.user = {"token" : token};
                    req.currentUser = {
                        email: currentUser.dataValues.email,
                        permissions: currentUser.dataValues.permissions
                    }

                    next();
                
                } catch (err) {

                    console.error(err.message);
                }
            } else {
                const payload = {"token" : jwtToken};
        
                req.user = payload;
                req.currentUser = {
                    email: currentUser.dataValues.email,
                    permissions: currentUser.dataValues.permissions
                }
                next();
            }
        });
        

        if (!jwtToken) {
            return res.status(403).json("Not authorized");
        };

        // const payload = jwt.verify(jwtToken, process.env.ACCESS_TOKEN_SECRET);
        
        // req.user = payload.user;
        // next();

    } catch (err) {
        console.error(err.message);
        return res.status(401).json("Token is not valid");
    };
};