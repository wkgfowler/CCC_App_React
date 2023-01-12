module.exports = (sequelize, DataTypes) => {
    const Token = sequelize.define("Token", {
        token_id: {
            type: DataTypes.UUID,
            allowNull: false,
            primaryKey: true,
            defaultValue: DataTypes.UUIDV4
        },
        token: {
            type: DataTypes.STRING,
            allowNull: false
        },
        user_id: {
            type: DataTypes.UUID,
            allowNull: false,
            unique: true,
            references: {
                model: "Users",
                key: "user_id"
            }
        }
    });

    return Token;
};