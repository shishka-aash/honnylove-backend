const pool = require('../config/database');
const bcrypt = require('bcryptjs');

class UserController {
    // Регистрация нового пользователя
    async addUser(req, res) {
        try {
            const { username, email, password, firstName, lastName } = req.body;

            // Валидация обязательных полей
            if (!username || !email || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username, email и password обязательны',
                });
            }

            // Проверка существования пользователя
            const [existingUser] = await pool.execute(
                'SELECT user_id FROM users WHERE username = ? OR email = ?',
                [username, email]
            );

            if (existingUser.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Пользователь с таким username или email уже существует',
                });
            }

            // Хеширование пароля
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Создание пользователя
            const query = `
                INSERT INTO users (username, email, password_hash, first_name, last_name, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, NOW(), NOW())
            `;

            const [result] = await pool.execute(query, [
                username,
                email,
                hashedPassword,
                firstName || null,
                lastName || null,
            ]);

            res.status(201).json({
                success: true,
                message: 'Пользователь успешно зарегистрирован',
                data: {
                    userId: result.insertId,
                    username,
                    email,
                    firstName,
                    lastName,
                },
            });
        } catch (error) {
            console.error('Ошибка при регистрации пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при регистрации',
            });
        }
    }

    // Получение информации о пользователе по имени
    async getUserByUsername(req, res) {
        try {
            const { username } = req.params;

            // Валидация параметра
            if (!username) {
                return res.status(400).json({
                    success: false,
                    message: 'Имя пользователя обязательно',
                });
            }

            // Получаем информацию о пользователе
            const [users] = await pool.execute(
                `SELECT 
                    user_id, 
                    username, 
                    email, 
                    first_name, 
                    last_name, 
                    created_at, 
                    updated_at 
                 FROM users 
                 WHERE username = ?`,
                [username]
            );

            // Проверяем, найден ли пользователь
            if (users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            const user = users[0];

            // Убираем чувствительные данные и форматируем даты (если нужно)
            const userData = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                createdAt: user.created_at,
                updatedAt: user.updated_at,
            };

            res.json({
                success: true,
                message: 'Информация о пользователе получена успешно',
                data: userData,
            });
        } catch (error) {
            console.error('Ошибка при получении пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при получении данных пользователя',
            });
        }
    }

    // В класс UserController добавьте метод для авторизации

// Авторизация пользователя
async login(req, res) {
    try {
        const { username, password } = req.body;

        // Валидация обязательных полей
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username и password обязательны',
            });
        }

        // Ищем пользователя по username или email
        const [users] = await pool.execute(
            `SELECT 
                user_id, 
                username, 
                email, 
                password_hash,
                first_name, 
                last_name
             FROM users 
             WHERE username = ? OR email = ?`,
            [username, username]
        );

        // Проверяем, найден ли пользователь
        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Неверное имя пользователя или пароль',
            });
        }

        const user = users[0];

        // Проверяем пароль
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Неверное имя пользователя или пароль',
            });
        }

        // Создаем JWT токен (нужно установить библиотеку jsonwebtoken)
        const jwt = require('jsonwebtoken');
        const token = jwt.sign(
            {
                userId: user.user_id,
                username: user.username,
                email: user.email
            },
            process.env.JWT_SECRET || 'your-secret-key', // Используйте переменные окружения
            { expiresIn: '24h' }
        );

        // Убираем пароль из ответа
        const userData = {
            userId: user.user_id,
            username: user.username,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
        };

        res.json({
            success: true,
            message: 'Авторизация успешна',
            data: {
                user: userData,
                token: token
            },
        });
    } catch (error) {
        console.error('Ошибка при авторизации:', error);
        res.status(500).json({
            success: false,
            message: 'Ошибка сервера при авторизации',
        });
    }
}

// Получение профиля пользователя (защищенный маршрут)
async getProfile(req, res) {
    try {
        const userId = req.userId; // Будет устанавливаться middleware

        const [users] = await pool.execute(
            `SELECT 
                user_id, 
                username, 
                email, 
                first_name, 
                last_name,
                created_at,
                updated_at
             FROM users 
             WHERE user_id = ?`,
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Пользователь не найден',
            });
        }

        const user = users[0];
        const userData = {
            userId: user.user_id,
            username: user.username,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            createdAt: user.created_at,
            updatedAt: user.updated_at,
        };

        res.json({
            success: true,
            message: 'Данные профиля получены успешно',
            data: userData,
        });
    } catch (error) {
        console.error('Ошибка при получении профиля:', error);
        res.status(500).json({
            success: false,
            message: 'Ошибка сервера при получении профиля',
        });
    }
}

    // Обновление данных пользователя
    async updateUser(req, res) {
        try {
            const {
                username,
                email,
                firstName,
                lastName,
                currentPassword,
                newPassword,
            } = req.body;

            if (!username) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Username обязателен для идентификации пользователя',
                });
            }

            // Получаем текущие данные пользователя
            const [userRows] = await pool.execute(
                'SELECT user_id, password_hash FROM users WHERE username = ?',
                [username]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            const userId = userRows[0].user_id;
            const updates = [];
            const params = [];

            // Проверка пароля если требуется его изменение
            if (newPassword) {
                if (!currentPassword) {
                    return res.status(400).json({
                        success: false,
                        message:
                            'Текущий пароль обязателен для изменения пароля',
                    });
                }

                // Проверяем текущий пароль
                const isValidPassword = await bcrypt.compare(
                    currentPassword,
                    userRows[0].password_hash
                );
                if (!isValidPassword) {
                    return res.status(401).json({
                        success: false,
                        message: 'Неверный текущий пароль',
                    });
                }

                // Хешируем новый пароль
                const saltRounds = 10;
                const hashedNewPassword = await bcrypt.hash(
                    newPassword,
                    saltRounds
                );
                updates.push('password_hash = ?');
                params.push(hashedNewPassword);
            }

            // Обновление email
            if (email) {
                // Проверяем, не используется ли email другим пользователем
                const [emailCheck] = await pool.execute(
                    'SELECT user_id FROM users WHERE email = ? AND user_id != ?',
                    [email, userId]
                );

                if (emailCheck.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: 'Email уже используется другим пользователем',
                    });
                }
                updates.push('email = ?');
                params.push(email);
            }

            // Обновление имени и фамилии
            if (firstName !== undefined) {
                updates.push('first_name = ?');
                params.push(firstName);
            }

            if (lastName !== undefined) {
                updates.push('last_name = ?');
                params.push(lastName);
            }

            // Если нет полей для обновления
            if (updates.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Нет данных для обновления',
                });
            }

            updates.push('updated_at = NOW()');
            params.push(userId);

            const query = `UPDATE users SET ${updates.join(
                ', '
            )} WHERE user_id = ?`;

            await pool.execute(query, params);

            res.json({
                success: true,
                message: 'Данные пользователя успешно обновлены',
            });
        } catch (error) {
            console.error('Ошибка при обновлении пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при обновлении данных',
            });
        }
    }
}

module.exports = new UserController();
