require('dotenv').config();
const {User, Token} = require('../models');
const app = require('../server');
const jwtRefreshGenerator = require('../utils/jwtRefreshGenerator');

module.exports = async (req, res, next) => {
    try {

        const {email} = req.body;

        const user = await User.findOne({
            where: {
                email: email
            }
        })

        const token = await Token.findOne({
            where: {
                user_id: user.user_id
            }
        })

        if (token) {
            return res.status(403).json("Token Invalid")
        }

        const refreshToken = Token.build({
            token: jwtRefreshGenerator(user.user_id),
            user_id: user.user_id
        });
        
        await refreshToken.save();

        next();
    } catch (err) {
        console.error(err.message);
        return res.status(401).json("Invalid User")
    }
}