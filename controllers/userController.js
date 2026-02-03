const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const tokenService = require('../services/tokenService');

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
                INSERT INTO users (username, email, password_hash, first_name, last_name, created_at, updated_at, roles)
                VALUES (?, ?, ?, ?, ?, NOW(), NOW(), 'user')
            `;

            const [result] = await pool.execute(query, [
                username,
                email,
                hashedPassword,
                firstName || null,
                lastName || null,
            ]);

            // Автоматическая авторизация после регистрации
            const [newUser] = await pool.execute(
                'SELECT user_id, username, email, first_name, last_name, roles FROM users WHERE user_id = ?',
                [result.insertId]
            );

            const user = newUser[0];
            
            // Генерируем токены
            const payload = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                roles: user.roles
            };

            const tokens = tokenService.generateTokens(payload);
            
            // Сохраняем refresh токен в базу
            await tokenService.saveRefreshToken(user.user_id, tokens.refreshToken);

            // Устанавливаем refresh токен в httpOnly cookie
            res.cookie('refreshToken', tokens.refreshToken, {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict'
            });

            const userData = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                roles: user.roles
            };

            res.status(201).json({
                success: true,
                message: 'Пользователь успешно зарегистрирован',
                data: {
                    user: userData,
                    accessToken: tokens.accessToken
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

    // Авторизация пользователя
    async login(req, res) {
        try {
            const { username, password } = req.body;

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
                    last_name,
                    roles
                 FROM users 
                 WHERE username = ? OR email = ?`,
                [username, username]
            );

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

            // Генерируем токены
            const payload = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                roles: user.roles
            };

            const tokens = tokenService.generateTokens(payload);
            
            // Сохраняем refresh токен в базу
            await tokenService.saveRefreshToken(user.user_id, tokens.refreshToken);

            // Убираем пароль из ответа
            const userData = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                roles: user.roles
            };

            // Устанавливаем refresh токен в httpOnly cookie
            res.cookie('refreshToken', tokens.refreshToken, {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict'
            });

            res.json({
                success: true,
                message: 'Авторизация успешна',
                data: {
                    user: userData,
                    accessToken: tokens.accessToken
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

    // Обновление access токена
    async refreshToken(req, res) {
        try {
            const { refreshToken } = req.cookies;

            if (!refreshToken) {
                return res.status(401).json({
                    success: false,
                    message: 'Отсутствует refresh token',
                });
            }

            // Валидируем refresh token
            const userData = tokenService.validateRefreshToken(refreshToken);
            const userFromDb = await tokenService.findUserByRefreshToken(refreshToken);

            if (!userData || !userFromDb) {
                return res.status(403).json({
                    success: false,
                    message: 'Неверный refresh token',
                });
            }

            // Генерируем новые токены
            const payload = {
                userId: userFromDb.user_id,
                username: userFromDb.username,
                email: userFromDb.email,
                roles: userFromDb.roles
            };

            const tokens = tokenService.generateTokens(payload);
            
            // Обновляем refresh токен в базе
            await tokenService.saveRefreshToken(userFromDb.user_id, tokens.refreshToken);

            // Устанавливаем новый refresh токен в cookie
            res.cookie('refreshToken', tokens.refreshToken, {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict'
            });

            res.json({
                success: true,
                message: 'Токен обновлен',
                data: {
                    accessToken: tokens.accessToken
                },
            });
        } catch (error) {
            console.error('Ошибка при обновлении токена:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при обновлении токена',
            });
        }
    }

    // Выход пользователя
    async logout(req, res) {
        try {
            const { refreshToken } = req.cookies;
            
            if (refreshToken) {
                const userData = tokenService.validateRefreshToken(refreshToken);
                if (userData) {
                    await tokenService.removeRefreshToken(userData.userId);
                }
            }

            // Очищаем cookie
            res.clearCookie('refreshToken');

            res.json({
                success: true,
                message: 'Выход выполнен успешно',
            });
        } catch (error) {
            console.error('Ошибка при выходе:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при выходе',
            });
        }
    }

    // Получение профиля пользователя (защищенный маршрут)
    async getProfile(req, res) {
        try {
            const userId = req.user.userId;

            const [users] = await pool.execute(
                `SELECT 
                    user_id, 
                    username, 
                    email, 
                    first_name, 
                    last_name,
                    roles,
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
                roles: user.roles,
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

    // Получение пользователя по username (только для админов)
    async getUserByUsername(req, res) {
        try {
            const { username } = req.params;

            if (!username) {
                return res.status(400).json({
                    success: false,
                    message: 'Имя пользователя обязательно',
                });
            }

            const [users] = await pool.execute(
                `SELECT 
                    user_id, 
                    username, 
                    email, 
                    first_name, 
                    last_name,
                    roles,
                    created_at, 
                    updated_at 
                 FROM users 
                 WHERE username = ?`,
                [username]
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
                roles: user.roles,
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

    // Получение всех пользователей (только для админов)
    async getAllUsers(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;

            // Получаем пользователей с пагинацией
            const [users] = await pool.execute(
                `SELECT 
                    user_id, 
                    username, 
                    email, 
                    first_name, 
                    last_name,
                    roles,
                    created_at, 
                    updated_at 
                 FROM users 
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?`,
                [limit, offset]
            );

            // Получаем общее количество пользователей
            const [countResult] = await pool.execute(
                'SELECT COUNT(*) as total FROM users'
            );
            const total = countResult[0].total;

            const usersData = users.map(user => ({
                userId: user.user_id,
                username: user.username,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                roles: user.roles,
                createdAt: user.created_at,
                updatedAt: user.updated_at,
            }));

            res.json({
                success: true,
                message: 'Список пользователей получен успешно',
                data: {
                    users: usersData,
                    pagination: {
                        page,
                        limit,
                        total,
                        pages: Math.ceil(total / limit)
                    }
                },
            });
        } catch (error) {
            console.error('Ошибка при получении списка пользователей:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при получении списка пользователей',
            });
        }
    }

    // Обновление данных пользователя
    async updateUser(req, res) {
        try {
            const userId = req.user.userId;
            const {
                email,
                firstName,
                lastName,
                currentPassword,
                newPassword,
            } = req.body;

            // Получаем текущие данные пользователя
            const [userRows] = await pool.execute(
                'SELECT user_id, password_hash FROM users WHERE user_id = ?',
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

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

            // Получаем обновленные данные пользователя
            const [updatedUser] = await pool.execute(
                'SELECT user_id, username, email, first_name, last_name, roles FROM users WHERE user_id = ?',
                [userId]
            );

            const user = updatedUser[0];
            const userData = {
                userId: user.user_id,
                username: user.username,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                roles: user.roles
            };

            res.json({
                success: true,
                message: 'Данные пользователя успешно обновлены',
                data: userData,
            });
        } catch (error) {
            console.error('Ошибка при обновлении пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при обновлении данных',
            });
        }
    }

    // Обновление роли пользователя (только для админов)
    async updateUserRole(req, res) {
        try {
            const { userId } = req.params;
            const { roles } = req.body;

            if (!userId || !roles) {
                return res.status(400).json({
                    success: false,
                    message: 'ID пользователя и роль обязательны',
                });
            }

            // Проверяем существование пользователя
            const [userRows] = await pool.execute(
                'SELECT user_id FROM users WHERE user_id = ?',
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            // Обновляем роль
            await pool.execute(
                'UPDATE users SET roles = ?, updated_at = NOW() WHERE user_id = ?',
                [roles, userId]
            );

            // Получаем обновленные данные
            const [updatedUser] = await pool.execute(
                'SELECT user_id, username, email, roles FROM users WHERE user_id = ?',
                [userId]
            );

            const user = updatedUser[0];

            res.json({
                success: true,
                message: 'Роль пользователя успешно обновлена',
                data: {
                    userId: user.user_id,
                    username: user.username,
                    email: user.email,
                    roles: user.roles
                },
            });
        } catch (error) {
            console.error('Ошибка при обновлении роли пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при обновлении роли',
            });
        }
    }

    // Удаление пользователя (только для админов)
    async deleteUser(req, res) {
        try {
            const { userId } = req.params;

            if (!userId) {
                return res.status(400).json({
                    success: false,
                    message: 'ID пользователя обязателен',
                });
            }

            // Проверяем существование пользователя
            const [userRows] = await pool.execute(
                'SELECT user_id FROM users WHERE user_id = ?',
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Пользователь не найден',
                });
            }

            // Нельзя удалить самого себя
            if (parseInt(userId) === req.user.userId) {
                return res.status(400).json({
                    success: false,
                    message: 'Нельзя удалить свой собственный аккаунт',
                });
            }

            // Удаляем пользователя
            await pool.execute('DELETE FROM users WHERE user_id = ?', [userId]);

            res.json({
                success: true,
                message: 'Пользователь успешно удален',
            });
        } catch (error) {
            console.error('Ошибка при удалении пользователя:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при удалении пользователя',
            });
        }
    }

    // Проверка аутентификации
    async checkAuth(req, res) {
        try {
            const userId = req.user.userId;

            const [users] = await pool.execute(
                'SELECT user_id, username, email, first_name, last_name, roles FROM users WHERE user_id = ?',
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
                roles: user.roles
            };

            res.json({
                success: true,
                message: 'Пользователь аутентифицирован',
                data: userData,
            });
        } catch (error) {
            console.error('Ошибка при проверке аутентификации:', error);
            res.status(500).json({
                success: false,
                message: 'Ошибка сервера при проверке аутентификации',
            });
        }
    }
}

module.exports = new UserController();