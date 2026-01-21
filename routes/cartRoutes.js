const express = require('express');
const router = express.Router();
const cartController = require('../controllers/cartController');

// Получить корзину пользователя
router.get('/:username', cartController.getCartByUsername);

// Добавить товар в корзину
router.post('/add', cartController.addToCart);

// Удалить товар из корзины
router.delete('/remove', cartController.removeFromCart);

// Обновить количество товара
router.put('/update', cartController.updateCartQuantity);

// Очистить всю корзину пользователя
router.delete('/clear', cartController.clearCart);

module.exports = router;
