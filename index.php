<?php
// ====================================================================================
// КОНФИГУРАЦИЯ И КОНСТАНТЫ (бывший config.php)
// ====================================================================================
define('USERS_FILE', __DIR__ . '/users.json');
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_DURATION', 60 * 15); // 15 минут блокировка
define('INACTIVITY_LOCKOUT_DURATION', 30 * 24 * 60 * 60); // 1 месяц в секундах

// ====================================================================================
// СТАРТ СЕССИИ
// ====================================================================================
session_start();

// ====================================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (бывший functions.php)
// ====================================================================================

function getUsers() {
    if (!file_exists(USERS_FILE)) {
        return [];
    }
    $json_data = file_get_contents(USERS_FILE);
    return json_decode($json_data, true) ?: [];
}

function saveUsers($users) {
    file_put_contents(USERS_FILE, json_encode(array_values($users), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); // array_values для корректного JSON массива
}

function findUserByUsername($username) {
    $users = getUsers();
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return $user;
        }
    }
    return null;
}

function findUserById($id) {
    $users = getUsers();
    foreach ($users as $key => $user) {
        if ($user['id'] === $id) {
            return ['key' => $key, 'data' => $user];
        }
    }
    return null;
}

function generateUniqueId() {
    return uniqid('user_', true);
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isLoggedIn() && isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin';
}

function redirect($action, $params = []) {
    $query_string = http_build_query(array_merge(['action' => $action], $params));
    header("Location: index.php?" . $query_string);
    exit();
}

function setMessage($type, $message) {
    // Сообщения теперь будут передаваться через GET параметры при редиректе
    // Эта функция не будет напрямую использоваться для сессионных флеш-сообщений
    // Вместо этого, при редиректе будем добавлять message_type и message_text в $params
}

function displayMessage() {
    $output = '';
    if (isset($_GET['message_text']) && isset($_GET['message_type'])) {
        $message_text = htmlspecialchars(urldecode($_GET['message_text']));
        $message_type = htmlspecialchars($_GET['message_type']);
        $output = "<div class='message {$message_type}'>{$message_text}</div>";
    }
    // Очищаем GET-параметры сообщения из URL после отображения, если это нужно (сложнее без перезагрузки)
    // Для простоты оставим их в URL до следующего действия
    return $output;
}

// ====================================================================================
// ОБРАБОТКА POST-ЗАПРОСОВ И ЛОГИКА ДЕЙСТВИЙ
// ====================================================================================
$action = $_GET['action'] ?? (isLoggedIn() ? 'dashboard' : 'login');
$page_title = '';
$error = ''; // Общая переменная для ошибок формы
$success = ''; // Общая переменная для сообщений успеха (если не через GET)

// --- Логика для LOGIN ---
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_submit'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($password)) {
        $error = 'Пожалуйста, введите имя пользователя и пароль.';
    } else {
        $users_data = getUsers(); 
        $user_to_check_key = null;
        $user_to_check_data = null;

        foreach ($users_data as $key => $u) {
            if ($u['username'] === $username) {
                $user_to_check_key = $key;
                $user_to_check_data = $u;
                break;
            }
        }

        if ($user_to_check_data) {
            // 1. Проверка и возможная блокировка по неактивности
            if (isset($user_to_check_data['last_login_time']) && 
                $user_to_check_data['last_login_time'] != 0 && 
                (time() - $user_to_check_data['last_login_time']) > INACTIVITY_LOCKOUT_DURATION) {
                
                // Блокируем, только если он еще не заблокирован (по любой причине)
                // или если текущая блокировка не по причине 'inactive' (чтобы не перезаписывать)
                if (!isset($user_to_check_data['is_locked']) || $user_to_check_data['is_locked'] === false || 
                    (isset($user_to_check_data['is_locked']) && $user_to_check_data['is_locked'] === true && (!isset($user_to_check_data['lock_reason']) || $user_to_check_data['lock_reason'] !== 'inactive'))) {
                    
                    $users_data[$user_to_check_key]['is_locked'] = true;
                    $users_data[$user_to_check_key]['lock_reason'] = 'inactive';
                    saveUsers($users_data);
                    // Обновляем локальную копию для дальнейших проверок в этом запросе
                    $user_to_check_data['is_locked'] = true; 
                    $user_to_check_data['lock_reason'] = 'inactive';
                }
            }

            // 2. Проверка, если пользователь ЗАБЛОКИРОВАН (по любой причине, включая неактивность)
            if (isset($user_to_check_data['is_locked']) && $user_to_check_data['is_locked'] === true) {
                if (isset($user_to_check_data['lock_reason']) && $user_to_check_data['lock_reason'] === 'inactive') {
                    $error = "Учетная запись заблокирована из-за неактивности. Обратитесь к администратору.";
                } elseif (isset($user_to_check_data['lock_reason']) && $user_to_check_data['lock_reason'] === 'attempts') {
                    // Проверяем, не истекло ли время временной блокировки по попыткам
                    if (isset($user_to_check_data['last_attempt_time']) && (time() - $user_to_check_data['last_attempt_time']) < LOCKOUT_DURATION) {
                        $error = "Учетная запись временно заблокирована из-за попыток входа. Попробуйте позже.";
                    } else {
                        // Время блокировки истекло, разблокируем для этой попытки входа
                        $users_data[$user_to_check_key]['failed_attempts'] = 0;
                        $users_data[$user_to_check_key]['is_locked'] = false;
                        unset($users_data[$user_to_check_key]['lock_reason']);
                        // Не сохраняем сразу, дадим шанс ввести пароль. Сохраним при успехе/неудаче пароля.
                        $user_to_check_data['is_locked'] = false; // Обновляем локальную копию
                        unset($user_to_check_data['lock_reason']);
                    }
                } else {
                     // Общая блокировка без конкретной известной причины (маловероятно с текущей логикой, но на всякий случай)
                    $error = "Учетная запись заблокирована. Обратитесь к администратору.";
                }
            }
            // Эта проверка больше не нужна, так как выше мы уже обработали временную блокировку по попыткам
            // elseif (isset($user_to_check_data['last_attempt_time']) && ($user_to_check_data['failed_attempts'] ?? 0) >= MAX_LOGIN_ATTEMPTS && (time() - $user_to_check_data['last_attempt_time']) < LOCKOUT_DURATION) {
            // $error = "Учетная запись временно заблокирована. Попробуйте позже.";
            // } 
            
            // Если после всех проверок выше $error все еще пуст, продолжаем с паролем
            if (empty($error)) {
                if ($password === $user_to_check_data['password']) {
                    $_SESSION['user_id'] = $user_to_check_data['id'];
                    $_SESSION['username'] = $user_to_check_data['username'];
                    $_SESSION['user_role'] = $user_to_check_data['role'];

                    $users_data[$user_to_check_key]['failed_attempts'] = 0;
                    $users_data[$user_to_check_key]['last_login_time'] = time();
                    $users_data[$user_to_check_key]['is_locked'] = false; // Убедимся, что разблокирован
                    unset($users_data[$user_to_check_key]['lock_reason']);
                    saveUsers($users_data);
                    redirect('dashboard', ['message_type' => 'success', 'message_text' => urlencode('Вы успешно авторизовались!')]);
                } else { // Пароль неверный
                    $users_data[$user_to_check_key]['failed_attempts'] = ($user_to_check_data['failed_attempts'] ?? 0) + 1;
                    $users_data[$user_to_check_key]['last_attempt_time'] = time();
                    if ($users_data[$user_to_check_key]['failed_attempts'] >= MAX_LOGIN_ATTEMPTS) {
                        $users_data[$user_to_check_key]['is_locked'] = true;
                        $users_data[$user_to_check_key]['lock_reason'] = 'attempts';
                        $error = "Вы ввели неверный пароль 3 раза. Учетная запись заблокирована.";
                    } else {
                        $attempts_left = MAX_LOGIN_ATTEMPTS - $users_data[$user_to_check_key]['failed_attempts'];
                        $error = "Неверный логин или пароль. Осталось попыток: " . $attempts_left;
                    }
                    saveUsers($users_data);
                }
            }
        } else { // Пользователь не найден
            $error = 'Пользователь с таким именем не найден.';
        }
    }
}

// --- Логика для REGISTER ---
elseif ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register_submit'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $password_confirm = trim($_POST['password_confirm']);

    if (empty($username) || empty($password) || empty($password_confirm)) {
        $error = 'Все поля обязательны для заполнения.';
    } elseif ($password !== $password_confirm) {
        $error = 'Пароли не совпадают.';
    } elseif (strlen($password) < 6) {
        $error = 'Пароль должен быть не менее 6 символов.';
    } elseif (findUserByUsername($username)) {
        $error = 'Пользователь с таким именем уже существует.';
    } else {
        $users_data = getUsers();
        $newUser = [
            'id' => generateUniqueId(),
            'username' => $username,
            'password' => $password, // Без хеширования
            'role' => 'user',
            'failed_attempts' => 0,
            'last_attempt_time' => 0,
            'is_locked' => false,
            'last_login_time' => 0
        ];
        $users_data[] = $newUser;
        saveUsers($users_data);
        redirect('login', ['message_type' => 'success', 'message_text' => urlencode('Регистрация прошла успешно! Теперь вы можете войти.')]);
    }
}

// --- Логика для CHANGE_PASSWORD ---
elseif ($action === 'change_password' && isLoggedIn() && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password_submit'])) {
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error = 'Все поля обязательны для заполнения.';
    } elseif ($new_password !== $confirm_password) {
        $error = 'Новые пароли не совпадают.';
    } elseif (strlen($new_password) < 6) {
        $error = 'Новый пароль должен быть не менее 6 символов.';
    } else {
        $users_data = getUsers();
        $user_info = findUserById($_SESSION['user_id']);

        if ($user_info && $current_password === $user_info['data']['password']) {
            $users_data[$user_info['key']]['password'] = $new_password; // Без хеширования
            saveUsers($users_data);
            redirect('dashboard', ['message_type' => 'success', 'message_text' => urlencode('Пароль успешно изменен.')]);
        } else {
            $error = 'Текущий пароль введен неверно.';
        }
    }
}

// --- Логика для ADMIN ACTIONS (бывший admin_actions.php и часть admin.php) ---
elseif ($action === 'admin' && isAdmin() && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $admin_action = $_POST['admin_form_action'] ?? null;
    $user_id_to_act = $_POST['user_id'] ?? null;
    $users_data = getUsers(); // Получаем свежие данные

    if ($admin_action === 'add_user') {
        $new_username = trim($_POST['new_username']);
        $new_password = trim($_POST['new_password']);
        $new_role = $_POST['new_role'];
        if (empty($new_username) || empty($new_password) || empty($new_role)) {
            $error = 'Все поля для добавления пользователя обязательны.';
        } elseif (strlen($new_password) < 6) { $error = 'Пароль должен быть не менее 6 символов.'; }
        elseif (findUserByUsername($new_username)) { $error = 'Пользователь с таким именем уже существует.'; }
        elseif (!in_array($new_role, ['user', 'admin'])) { $error = 'Недопустимая роль пользователя.'; }
        else {
            $newUser = ['id' => generateUniqueId(), 'username' => $new_username, 'password' => $new_password, 'role' => $new_role, 'failed_attempts' => 0, 'last_attempt_time' => 0, 'is_locked' => false, 'last_login_time' => 0];
            $users_data[] = $newUser;
            saveUsers($users_data);
            redirect('admin', ['message_type' => 'success', 'message_text' => urlencode("Пользователь {$new_username} успешно добавлен.")]);
        }
    } elseif ($user_id_to_act) {
        $user_info = null;
        $user_key_to_act = null;
        foreach($users_data as $key => $u) {
            if ($u['id'] === $user_id_to_act) {
                $user_info = $u;
                $user_key_to_act = $key;
                break;
            }
        }

        if ($user_info) {
            if ($admin_action === 'admin_change_password') {
                $new_user_password = $_POST['new_user_password'];
                if (empty($new_user_password) || strlen($new_user_password) < 6) {
                     redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Новый пароль должен быть не менее 6 символов.')]);
                } else {
                    $users_data[$user_key_to_act]['password'] = $new_user_password;
                    saveUsers($users_data);
                    redirect('admin', ['message_type' => 'success', 'message_text' => urlencode("Пароль для {$user_info['username']} изменен.")]);
                }
            } elseif ($admin_action === 'delete_user') {
                if ($user_info['id'] === $_SESSION['user_id']) {
                     redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Вы не можете удалить самого себя.')]);
                } elseif ($user_info['username'] === 'admin' && $user_info['role'] === 'admin' && count(array_filter($users_data, function($u) { return $u['role'] === 'admin'; })) <=1 ) {
                     redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Нельзя удалить единственного администратора.')]);
                } else {
                    unset($users_data[$user_key_to_act]);
                    saveUsers($users_data);
                    redirect('admin', ['message_type' => 'success', 'message_text' => urlencode("Пользователь {$user_info['username']} удален.")]);
                }
            } elseif ($admin_action === 'unlock_user') {
                $users_data[$user_key_to_act]['is_locked'] = false;
                $users_data[$user_key_to_act]['failed_attempts'] = 0;
                unset($users_data[$user_key_to_act]['lock_reason']);
                saveUsers($users_data);
                redirect('admin', ['message_type' => 'success', 'message_text' => urlencode("Пользователь {$user_info['username']} разблокирован.")]);
            } elseif ($admin_action === 'edit_user_role') {
                $new_role_for_user = $_POST['new_role_for_user'];
                // ... (логика проверки смены роли, аналогичная той, что была в admin_actions.php)
                 if ($user_info['id'] === $_SESSION['user_id'] && $user_info['role'] === 'admin' && $new_role_for_user !== 'admin') {
                    $admin_count = 0; foreach ($users_data as $u) { if ($u['role'] === 'admin') $admin_count++; }
                    if ($admin_count <= 1) {
                         redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Нельзя лишить себя прав администратора.')]);
                    }
                }
                // (прочие проверки для 'admin')
                if (in_array($new_role_for_user, ['user', 'admin'])) {
                    $users_data[$user_key_to_act]['role'] = $new_role_for_user;
                    saveUsers($users_data);
                     redirect('admin', ['message_type' => 'success', 'message_text' => urlencode("Роль для {$user_info['username']} изменена.")]);
                } else {
                     redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Недопустимая роль.')]);
                }
            }
        } else {
             redirect('admin', ['message_type' => 'error', 'message_text' => urlencode('Пользователь не найден.')]);
        }
    }
}


// --- Логика для LOGOUT ---
if ($action === 'logout') {
    session_unset();
    session_destroy();
    redirect('login', ['message_type' => 'success', 'message_text' => urlencode('Вы успешно вышли из системы.')]);
}

// Проверка доступа к защищенным страницам
if (in_array($action, ['dashboard', 'change_password']) && !isLoggedIn()) {
    redirect('login', ['message_type' => 'error', 'message_text' => urlencode('Доступ запрещен. Пожалуйста, войдите.')]);
}
if ($action === 'admin' && !isAdmin()) {
     redirect(isLoggedIn() ? 'dashboard' : 'login', ['message_type' => 'error', 'message_text' => urlencode('Доступ запрещен.')]);
}


// ====================================================================================
// HTML ВЫВОД СТРАНИЦ
// ====================================================================================
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>
        <?php
        switch ($action) {
            case 'login': echo 'Вход'; break;
            case 'register': echo 'Регистрация'; break;
            case 'dashboard': echo 'Панель пользователя'; break;
            case 'change_password': echo 'Смена пароля'; break;
            case 'admin': echo 'Панель администратора'; break;
            default: echo 'Система аутентификации';
        }
        ?>
    </title>
    <style>
        /* Содержимое файла css/style.css вставляется сюда */
        body{font-family:Arial,sans-serif;margin:0;padding:20px;background-color:#f4f4f4;color:#333}.container{max-width:600px;margin:20px auto;padding:20px;background-color:#fff;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.1)}h1,h2{color:#333;text-align:center}form{display:flex;flex-direction:column}label{margin-bottom:5px;font-weight:700}input[type=text],input[type=password],input[type=email],select{padding:10px;margin-bottom:15px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}button{padding:10px 15px;background-color:#5cb85c;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}button:hover{background-color:#4cae4c}a{color:#007bff;text-decoration:none}a:hover{text-decoration:underline}.message{padding:10px;margin-bottom:15px;border-radius:4px;text-align:center}.message.success{background-color:#d4edda;color:#155724;border:1px solid #c3e6cb}.message.error{background-color:#f8d7da;color:#721c24;border:1px solid #f5c6cb}nav{margin-bottom:20px;text-align:center}nav a{margin:0 10px}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background-color:#f2f2f2}.actions a,.actions button{margin-right:5px;font-size:12px;padding:5px 8px}.actions button.delete{background-color:#d9534f}.actions button.delete:hover{background-color:#c9302c}.actions button.unlock{background-color:#f0ad4e}.actions button.unlock:hover{background-color:#ec971f}
        /* Дополнительные стили для форм админки, если нужны */
        .admin-user-actions form { display: inline-block; margin-bottom: 5px; }
        .admin-user-actions input[type="password"] { width: 120px; padding: 5px; margin-bottom:0; margin-right: 5px; }
    </style>
</head>
<body>
    <div class="container <?php if ($action === 'admin') echo 'admin-container" style="max-width: 900px;'; else echo '"'; ?>">
        <?php echo displayMessage(); // Отображаем сообщения из GET ?>
        <?php if (!empty($error)): // Отображаем ошибки текущей формы (если не было редиректа) ?>
            <div class="message error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php // --------------- LOGIN PAGE --------------- ?>
        <?php if ($action === 'login'): ?>
            <h1>Вход в систему</h1>
            <form action="index.php?action=login" method="POST">
                <input type="hidden" name="login_submit" value="1">
                <div>
                    <label for="username">Имя пользователя:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                </div>
                <div>
                    <label for="password">Пароль:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Войти</button>
            </form>
            <p style="text-align: center; margin-top: 15px;">
                Нет аккаунта? <a href="index.php?action=register">Зарегистрироваться</a>
            </p>

        <?php // --------------- REGISTER PAGE --------------- ?>
        <?php elseif ($action === 'register'): ?>
            <h1>Регистрация</h1>
            <form action="index.php?action=register" method="POST">
                <input type="hidden" name="register_submit" value="1">
                <div>
                    <label for="username">Имя пользователя:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                </div>
                <div>
                    <label for="password">Пароль:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div>
                    <label for="password_confirm">Подтвердите пароль:</label>
                    <input type="password" id="password_confirm" name="password_confirm" required>
                </div>
                <button type="submit">Зарегистрироваться</button>
            </form>
            <p style="text-align: center; margin-top: 15px;">
                Уже есть аккаунт? <a href="index.php?action=login">Войти</a>
            </p>

        <?php // --------------- DASHBOARD PAGE --------------- ?>
        <?php elseif ($action === 'dashboard' && isLoggedIn()): ?>
            <h1>Добро пожаловать, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
            <nav>
                <a href="index.php?action=change_password">Сменить пароль</a>
                <?php if (isAdmin()): ?>
                    <a href="index.php?action=admin">Панель администратора</a>
                <?php endif; ?>
                <a href="index.php?action=logout">Выйти</a>
            </nav>
            <p>Ваша роль: <?php echo htmlspecialchars($_SESSION['user_role']); ?></p>
            <?php
            $currentUserDashboard = findUserById($_SESSION['user_id']);
            if ($currentUserDashboard && isset($currentUserDashboard['data']['last_login_time']) && $currentUserDashboard['data']['last_login_time'] > 0):
            ?>
                <p>Последний вход: <?php echo date('d.m.Y H:i:s', $currentUserDashboard['data']['last_login_time']); ?></p>
            <?php else: ?>
                <p>Это ваш первый вход или информация о последнем входе отсутствует.</p>
            <?php endif; ?>

        <?php // --------------- CHANGE PASSWORD PAGE --------------- ?>
        <?php elseif ($action === 'change_password' && isLoggedIn()): ?>
            <h1>Смена пароля</h1>
            <form action="index.php?action=change_password" method="POST">
                <input type="hidden" name="change_password_submit" value="1">
                <div>
                    <label for="current_password">Текущий пароль:</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                <div>
                    <label for="new_password">Новый пароль:</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div>
                    <label for="confirm_password">Подтвердите новый пароль:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <button type="submit">Изменить пароль</button>
            </form>
            <p style="text-align: center; margin-top: 15px;"><a href="index.php?action=dashboard">Вернуться в панель</a></p>

        <?php // --------------- ADMIN PAGE --------------- ?>
        <?php elseif ($action === 'admin' && isAdmin()): ?>
            <h1>Панель администратора</h1>
            <nav>
                <a href="index.php?action=dashboard">Моя панель</a>
                <a href="index.php?action=logout">Выйти</a>
            </nav>

            <h2>Добавить нового пользователя</h2>
            <form action="index.php?action=admin" method="POST">
                <input type="hidden" name="admin_form_action" value="add_user">
                <div><label for="new_username">Имя пользователя:</label><input type="text" id="new_username" name="new_username" required></div>
                <div><label for="new_password">Пароль:</label><input type="password" id="new_password" name="new_password" required></div>
                <div><label for="new_role">Роль:</label><select id="new_role" name="new_role"><option value="user">User</option><option value="admin">Admin</option></select></div>
                <button type="submit">Добавить пользователя</button>
            </form>
            <hr style="margin: 30px 0;">
            <h2>Список пользователей</h2>
            <table>
                <thead><tr><th>ID</th><th>Имя</th><th>Роль</th><th>Статус</th><th>Действия</th></tr></thead>
                <tbody>
                    <?php $all_users_list = getUsers(); ?>
                    <?php foreach ($all_users_list as $user_item): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($user_item['id']); ?></td>
                        <td><?php echo htmlspecialchars($user_item['username']); ?></td>
                        <td><?php echo htmlspecialchars($user_item['role']); ?></td>
                        <td>
                            <?php
                            if (isset($user_item['is_locked']) && $user_item['is_locked']) {
                                echo '<span style="color:red;">Заблокирован</span>';
                                if (isset($user_item['lock_reason'])) { echo ' (' . ($user_item['lock_reason'] === 'attempts' ? 'попытки' : 'неактивность') . ')';}
                            } else { echo '<span style="color:green;">Активен</span>'; }
                            ?>
                        </td>
                        <td class="admin-user-actions">
                            <form action="index.php?action=admin" method="POST">
                                <input type="hidden" name="admin_form_action" value="admin_change_password">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user_item['id']); ?>">
                                <input type="password" name="new_user_password" placeholder="Новый пароль" required>
                                <button type="submit">Сменить</button>
                            </form>
                            <?php if ($user_item['id'] !== $_SESSION['user_id']): ?>
                            <form action="index.php?action=admin" method="POST" onsubmit="return confirm('Удалить пользователя <?php echo htmlspecialchars($user_item['username']); ?>?');">
                                <input type="hidden" name="admin_form_action" value="delete_user">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user_item['id']); ?>">
                                <button type="submit" class="delete">Удалить</button>
                            </form>
                            <?php endif; ?>
                            <?php if (isset($user_item['is_locked']) && $user_item['is_locked']): ?>
                            <form action="index.php?action=admin" method="POST">
                                <input type="hidden" name="admin_form_action" value="unlock_user">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user_item['id']); ?>">
                                <button type="submit" class="unlock">Разблок.</button>
                            </form>
                            <?php endif; ?>
                            <form action="index.php?action=admin" method="POST">
                                <input type="hidden" name="admin_form_action" value="edit_user_role">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user_item['id']); ?>">
                                <select name="new_role_for_user" onchange="this.form.submit()" <?php if ($user_item['id'] === $_SESSION['user_id'] && $user_item['username'] === 'admin') echo 'disabled title="Роль основного администратора менять нельзя"'; ?>>
                                    <option value="user" <?php echo ($user_item['role'] === 'user' ? 'selected' : ''); ?>>User</option>
                                    <option value="admin" <?php echo ($user_item['role'] === 'admin' ? 'selected' : ''); ?>>Admin</option>
                                </select>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; // End of admin page ?>
    </div>
</body>
</html>