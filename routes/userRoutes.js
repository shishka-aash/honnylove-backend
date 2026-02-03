const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

// ============== ПУБЛИЧНЫЕ МАРШРУТЫ ==============

// Регистрация нового пользователя
router.post('/register', userController.addUser);

// Авторизация пользователя
router.post('/login', userController.login);

// Обновление токена
router.post('/refresh', userController.refreshToken);

// Выход пользователя
router.post('/logout', userController.logout);

// ============== ЗАЩИЩЕННЫЕ МАРШРУТЫ (для авторизованных пользователей) ==============

// Получение профиля текущего пользователя
router.get('/profile', 
    authMiddleware.authenticateToken, 
    userController.getProfile
);

// Обновление профиля текущего пользователя
router.put('/profile', 
    authMiddleware.authenticateToken, 
    userController.updateUser
);

// Проверка аутентификации
router.get('/check-auth', 
    authMiddleware.authenticateToken, 
    userController.checkAuth
);

// ============== АДМИНСКИЕ МАРШРУТЫ ==============

// Получение пользователя по username
router.get('/username/:username', 
    authMiddleware.authenticateToken, 
    authMiddleware.authorizeRole(['admin']), 
    userController.getUserByUsername
);

// Получение всех пользователей
router.get('/', 
    authMiddleware.authenticateToken, 
    authMiddleware.authorizeRole(['admin']), 
    userController.getAllUsers
);

// Обновление роли пользователя
router.put('/:userId/role', 
    authMiddleware.authenticateToken, 
    authMiddleware.authorizeRole(['admin']), 
    userController.updateUserRole
);

// Удаление пользователя
router.delete('/:userId', 
    authMiddleware.authenticateToken, 
    authMiddleware.authorizeRole(['admin']), 
    userController.deleteUser
);

module.exports = router;