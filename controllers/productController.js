const pool = require('../config/database');

class ProductController {
    /**
     * Просмотр всех продуктов
     * GET /api/products/getall
     */
    async getAllProducts(req, res) {
        try {
            const [products] = await pool.execute(
                'SELECT * FROM products ORDER BY created_at DESC'
            );

            if (products.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Продукты не найдены'
                });
            }

            res.status(200).json({
                success: true,
                message: 'Продукты успешно получены',
                data: {
                    total: products.length,
                    products
                }
            });
        } catch (error) {
            console.error('Ошибка при получении продуктов:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при получении продуктов'
            });
        }
    }

    /**
     * Просмотр конкретного товара по названию
     * GET /api/products/getby/:name
     */
    async getProductByName(req, res) {
        try {
            const { name } = req.params;

            if (!name || name.trim() === '') {
                return res.status(400).json({
                    success: false,
                    message: 'Название продукта обязательно'
                });
            }

            const [products] = await pool.execute(
                'SELECT * FROM products WHERE name LIKE ?',
                [`%${name}%`]
            );

            if (products.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Продукт не найден'
                });
            }

            res.status(200).json({
                success: true,
                message: 'Продукт успешно найден',
                data: {
                    count: products.length,
                    products
                }
            });
        } catch (error) {
            console.error('Ошибка при поиске продукта:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при поиске продукта'
            });
        }
    }

    /**
     * Добавление нового продукта
     * POST /api/products/addproduct
     */
    async addProduct(req, res) {
        const {
            name,
            description,
            price,
            category,
            image_url,
            stock_quantity,
        } = req.body;

        console.log('заголовки письма:');
        console.log(req.headers);
        console.log('тело письма');
        console.log(req.body);
        if (!name || !price || !category) {
            return res.status(400).json({
                success: false,
                message: 'Название, цена и категория обязательны',
            });
        }

        const [existingProduct] = await pool.execute(
            'SELECT product_id FROM products WHERE name = ?',
            [name]
        );

        if (existingProduct.length > 0) {
            return res.status(409).json({
                m: 'нет такого продукта',
            });
        }

        const query = `
            INSERT INTO products 
            (name, description, price, category, image_url, stock_quantity, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
        `;

        const [result] = await pool.execute(query, [
            name,
            description || null,
            price,
            category,
            image_url || null,
            stock_quantity || 0,
        ]);

        res.status(201).json({
            success: true,
            message: 'Продукт успешно добавлен',
            data: {
                productId: result.insertId,
                name,
                description,
                price,
                category,
                image_url,
                stock_quantity: stock_quantity || 0,
            },
        });
    }

    /**
     * Удаление продукта
     * DELETE /api/products/deleteproduct
     */
    async deleteProduct(req, res) {
        const { productId } = req.body;

        if (!productId) {
            return res.status(400).json({
                success: false,
                message: 'ID продукта обязателен',
            });
        }

        const [productRows] = await pool.execute(
            'SELECT product_id FROM products WHERE product_id = ?',
            [productId]
        );

        if (productRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Продукт не найден',
            });
        }

        const [cartItems] = await pool.execute(
            'SELECT cart_id FROM cart WHERE product_id = ?',
            [productId]
        );

        if (cartItems.length > 0) {
            return res.status(409).json({
                success: false,
                message:
                    'Невозможно удалить продукт: он находится в корзинах пользователей',
            });
        }

        const query = 'DELETE FROM products WHERE product_id = ?';
        const [result] = await pool.execute(query, [productId]);

        res.json({
            success: true,
            message: 'Продукт успешно удален',
            deletedProductId: productId,
        });
    }

    /**
     * Обновление данных продукта
     * PUT /api/products/updateproduct
     */
    async updateProduct(req, res) {
        const {
            productId,
            name,
            description,
            price,
            category,
            image_url,
            stock_quantity,
        } = req.body;

        if (!productId) {
            return res.status(400).json({
                success: false,
                message: 'ID продукта обязателен',
            });
        }

        const [productRows] = await pool.execute(
            'SELECT product_id FROM products WHERE product_id = ?',
            [productId]
        );

        if (productRows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Продукт не найден',
            });
        }

        if (name) {
            const [existingProduct] = await pool.execute(
                'SELECT product_id FROM products WHERE name = ? AND product_id != ?',
                [name, productId]
            );

            if (existingProduct.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Продукт с таким названием уже существует',
                });
            }
        }

        const updates = [];
        const params = [];

        if (name !== undefined) {
            updates.push('name = ?');
            params.push(name);
        }

        if (description !== undefined) {
            updates.push('description = ?');
            params.push(description);
        }

        if (price !== undefined) {
            updates.push('price = ?');
            params.push(price);
        }

        if (category !== undefined) {
            updates.push('category = ?');
            params.push(category);
        }

        if (image_url !== undefined) {
            updates.push('image_url = ?');
            params.push(image_url);
        }

        if (stock_quantity !== undefined) {
            updates.push('stock_quantity = ?');
            params.push(stock_quantity);
        }

        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Нет данных для обновления',
            });
        }

        updates.push('updated_at = NOW()');
        params.push(productId);

        const query = `UPDATE products SET ${updates.join(
            ', '
        )} WHERE product_id = ?`;
        await pool.execute(query, params);

        res.json({
            success: true,
            message: 'Данные продукта успешно обновлены',
        });
    }
}

module.exports = new ProductController();