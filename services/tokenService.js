const jwt = require('jsonwebtoken');
const pool = require('../config/database');

class TokenService {
    // Генерация токенов
    generateTokens(payload) {
        const accessToken = jwt.sign(
            payload,
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
        );

        const refreshToken = jwt.sign(
            payload,
            process.env.JWT_REFRESH_SECRET,
            { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
        );

        return { accessToken, refreshToken };
    }

    // Сохранение refresh токена в базу данных
    async saveRefreshToken(userId, refreshToken) {
        const query = `
            UPDATE users 
            SET refresh_token = ?, 
                updated_at = NOW() 
            WHERE user_id = ?
        `;
        
        await pool.execute(query, [refreshToken, userId]);
    }

    // Удаление refresh токена
    async removeRefreshToken(userId) {
        const query = `
            UPDATE users 
            SET refresh_token = NULL, 
                updated_at = NOW() 
            WHERE user_id = ?
        `;
        
        await pool.execute(query, [userId]);
    }

    // Валидация refresh токена
    validateRefreshToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        } catch (error) {
            return null;
        }
    }

    // Валидация access токена
    validateAccessToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        } catch (error) {
            return null;
        }
    }

    // Поиск пользователя по refresh токену
    async findUserByRefreshToken(refreshToken) {
        const [users] = await pool.execute(
            'SELECT user_id, username, email, roles FROM users WHERE refresh_token = ?',
            [refreshToken]
        );

        return users.length > 0 ? users[0] : null;
    }
}

module.exports = new TokenService();