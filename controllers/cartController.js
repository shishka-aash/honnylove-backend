const pool = require('../config/database');

class CartController {
    // Получить корзину пользователя
    async getCartByUsername(req, res) {
        try {
            const username = req.params.username;

            const query = `
                SELECT 
                    u.username,
                    u.email,
                    u.first_name,
                    u.last_name,
                    p.product_id,
                    p.name as product_name,
                    p.description,
                    p.price,
                    p.category,
                    p.image_url,
                    p.stock_quantity,
                    c.quantity,
                    c.added_at,
                    (p.price * c.quantity) as total_price
                FROM cart c
                JOIN users u ON c.user_id = u.user_id
                JOIN products p ON c.product_id = p.product_id
                WHERE u.username = ?
                ORDER BY c.added_at DESC
            `;

            const [rows] = await pool.execute(query, [username]);

            if (rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Корзина пользователя не найдена',
                });
            }

            res.json({
                success: true,
                data: rows,
                userInfo: {
                    username: rows[0].username,
                    email: rows[0].email,
                    firstName: rows[0].first_name,
                    lastName: rows[0].last_name,
                },
            });
        } catch (error) {
            console.error('Ошибка при получении корзины:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера',
            });
        }
    }

    // Очистить всю корзину пользователя
    async clearCart(req, res) {
        try {
            const { username } = req.body;

            if (!username) {
                return res.status(400).json({
                    success: false,
                    message: 'Username обязателен',
                });
            }

            // Сначала получаем user_id по username
            const [userRows] = await pool.execute(
                'SELECT user_id FROM users WHERE username = ?',
                [username]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            const userId = userRows[0].user_id;

            // Удаляем все товары из корзины пользователя
            const query = 'DELETE FROM cart WHERE user_id = ?';
            const [result] = await pool.execute(query, [userId]);

            res.json({
                success: true,
                message: 'Корзина полностью очищена',
                deletedItems: result.affectedRows,
            });
        } catch (error) {
            console.error('Ошибка при очистке корзины:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера',
            });
        }
    }

    // Добавить товар в корзину
    async addToCart(req, res) {
        try {
            const { username, productId, quantity = 1 } = req.body;

            // Сначала получаем user_id по username
            const [userRows] = await pool.execute(
                'SELECT user_id FROM users WHERE username = ?',
                [username]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            const userId = userRows[0].user_id;

            // Проверяем существование товара
            const [productRows] = await pool.execute(
                'SELECT * FROM products WHERE product_id = ?',
                [productId]
            );

            if (productRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Товар не найден',
                });
            }

            // Добавляем в корзину (используем ON DUPLICATE KEY UPDATE для обновления количества)
            const query = `
                INSERT INTO cart (user_id, product_id, quantity) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE quantity = quantity + ?
            `;

            await pool.execute(query, [userId, productId, quantity, quantity]);

            res.json({
                success: true,
                message: 'Товар добавлен в корзину',
            });
        } catch (error) {
            console.error('Ошибка при добавлении в корзину:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера',
            });
        }
    }

    // Удалить товар из корзины
    async removeFromCart(req, res) {
        try {
            const { username, productId } = req.body;

            const query = `
                DELETE c FROM cart c
                JOIN users u ON c.user_id = u.user_id
                WHERE u.username = ? AND c.product_id = ?
            `;

            const [result] = await pool.execute(query, [username, productId]);

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Товар не найден в корзине',
                });
            }

            res.json({
                success: true,
                message: 'Товар удален из корзины',
            });
        } catch (error) {
            console.error('Ошибка при удалении из корзины:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера',
            });
        }
    }

    // Обновить количество товара
    async updateCartQuantity(req, res) {
        try {
            const { username, productId, quantity } = req.body;

            if (quantity <= 0) {
                return this.removeFromCart(req, res);
            }

            const query = `
                UPDATE cart c
                JOIN users u ON c.user_id = u.user_id
                SET c.quantity = ?
                WHERE u.username = ? AND c.product_id = ?
            `;

            const [result] = await pool.execute(query, [
                quantity,
                username,
                productId,
            ]);

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Товар не найден в корзине',
                });
            }

            res.json({
                success: true,
                message: 'Количество товара обновлено',
            });
        } catch (error) {
            console.error('Ошибка при обновлении корзины:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера',
            });
        }
    }
}

module.exports = new CartController();
