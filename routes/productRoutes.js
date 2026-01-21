const express = require('express');
const router = express.Router();
const productController = require('../controllers/productController');

// Добавление нового продукта
router.post('/addproduct', productController.addProduct);

// Удаление продукта
router.delete('/deleteproduct', productController.deleteProduct);

// Обновление данных продукта
router.put('/updateproduct', productController.updateProduct);

// Просмотр всех продуктов
router.get('/getall', productController.getAllProducts);

// Просмотр конкретного товара по названию
router.get('/getby/:name', productController.getProductByName);

module.exports = router;
