const jwt = require('jsonwebtoken');
const pool = require('../config/database');

class AuthMiddleware {
    // Middleware для проверки Access Token
    authenticateToken = async (req, res, next) => {
        try {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json({
                    success: false,
                    message: 'Требуется аутентификация',
                });
            }

            jwt.verify(token, process.env.JWT_ACCESS_SECRET, async (err, decoded) => {
                if (err) {
                    return res.status(403).json({
                        success: false,
                        message: 'Неверный или просроченный токен',
                    });
                }

                // Проверяем, существует ли пользователь в базе
                const [users] = await pool.execute(
                    'SELECT user_id, username, email, roles FROM users WHERE user_id = ?',
                    [decoded.userId]
                );

                if (users.length === 0) {
                    return res.status(403).json({
                        success: false,
                        message: 'Пользователь не найден',
                    });
                }

                const user = users[0];
                
                // Сохраняем информацию о пользователе в запросе
                req.user = {
                    userId: user.user_id,
                    username: user.username,
                    email: user.email,
                    roles: user.roles
                };

                next();
            });
        } catch (error) {
            console.error('Ошибка аутентификации:', error);
            return res.status(500).json({
                success: false,
                message: 'Ошибка сервера при аутентификации',
            });
        }
    };

    // Middleware для проверки роли
    authorizeRole = (allowedRoles) => {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Требуется аутентификация',
                });
            }

            const userRoles = req.user.roles.split(',').map(role => role.trim());
            const hasRequiredRole = allowedRoles.some(role => userRoles.includes(role));

            if (!hasRequiredRole) {
                return res.status(403).json({
                    success: false,
                    message: 'Недостаточно прав для выполнения операции',
                });
            }

            next();
        };
    };
}

module.exports = new AuthMiddleware();