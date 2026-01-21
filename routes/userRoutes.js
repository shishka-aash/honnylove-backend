const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

// Регистрация нового пользователя
router.post('/adduser', userController.addUser);

// Обновление данных пользователя
router.put('/updateuser', userController.updateUser);

// Получение информации о пользователе по имени
router.get('/:username', userController.getUserByUsername);

// Авторизация пользователя
router.post('/login', userController.login);

module.exports = router;
