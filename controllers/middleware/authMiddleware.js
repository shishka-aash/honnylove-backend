const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    try {
        // Получаем токен из заголовка Authorization
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: 'Токен не предоставлен',
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Верифицируем токен
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        
        // Добавляем данные пользователя в запрос
        req.userId = decoded.userId;
        req.username = decoded.username;
        req.email = decoded.email;
        
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Токен истек',
            });
        }
        
        return res.status(401).json({
            success: false,
            message: 'Неверный токен',
        });
    }
};

module.exports = authMiddleware;