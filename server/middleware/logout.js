const jwt = require('jsonwebtoken');
require('dotenv').config();
const {Token} = require('../models');
const jwtGenerator = require('../utils/jwtGenerator');

module.exports = async (req, res, next) => {

    try {
        const jwtToken = req.header("token")
        const load = jwt.verify(jwtToken, process.env.ACCESS_TOKEN_SECRET);

        const refreshToken = await Token.findOne({
            where: {
                user_id: load.user
            }
        });

        await refreshToken.destroy();
        
        next();
    } catch (err) {
        console.error(err.message);
        res.status(500).json("Server Error");
    }
}