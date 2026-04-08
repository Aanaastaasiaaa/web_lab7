<?php
// functions.php - Общие функции (DRY)

require_once 'config.php';

// Валидация данных формы
function validateFormData($data) {
    $errors = [];
    
    // 1. ФИО
    if (empty($data['full_name'])) {
        $errors['full_name'] = 'ФИО обязательно для заполнения';
    } elseif (!preg_match('/^[а-яА-ЯёЁa-zA-Z\s-]+$/u', $data['full_name'])) {
        $errors['full_name'] = 'ФИО может содержать только буквы, пробелы и дефисы';
    } elseif (strlen($data['full_name']) > 150) {
        $errors['full_name'] = 'ФИО не должно превышать 150 символов';
    }
    
    // 2. Телефон
    if (empty($data['phone'])) {
        $errors['phone'] = 'Телефон обязателен для заполнения';
    } elseif (!preg_match('/^[\+\d\s\-\(\)]{6,20}$/', $data['phone'])) {
        $errors['phone'] = 'Телефон может содержать только цифры, пробелы, дефисы, скобки и + (6-20 символов)';
    }
    
    // 3. Email
    if (empty($data['email'])) {
        $errors['email'] = 'Email обязателен для заполнения';
    } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = 'Некорректный формат email (пример: name@domain.com)';
    }
    
    // 4. Дата рождения
    if (empty($data['birth_date'])) {
        $errors['birth_date'] = 'Дата рождения обязательна';
    } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $data['birth_date'])) {
        $errors['birth_date'] = 'Дата должна быть в формате ГГГГ-ММ-ДД';
    } else {
        $date = DateTime::createFromFormat('Y-m-d', $data['birth_date']);
        if (!$date || $date > new DateTime()) {
            $errors['birth_date'] = 'Некорректная дата';
        }
    }
    
    // 5. Пол
    if (empty($data['gender'])) {
        $errors['gender'] = 'Выберите пол';
    } elseif (!in_array($data['gender'], ['male', 'female'])) {
        $errors['gender'] = 'Некорректное значение пола';
    }
    
    // 6. Языки (исправлена проверка для безопасности)
    if (empty($data['languages']) || !is_array($data['languages'])) {
        $errors['languages'] = 'Выберите хотя бы один язык программирования';
    } else {
        foreach ($data['languages'] as $lang_id) {
            // Приведение к int для безопасности
            $lang_id = (int)$lang_id;
            if ($lang_id < 1 || $lang_id > 12) {
                $errors['languages'] = 'Выбран недопустимый язык программирования';
                break;
            }
        }
    }
    
    // 7. Биография
    if (empty($data['biography'])) {
        $errors['biography'] = 'Биография обязательна для заполнения';
    } elseif (strlen($data['biography']) > 5000) {
        $errors['biography'] = 'Биография не должна превышать 5000 символов';
    }
    
    // 8. Чекбокс
    if (!isset($data['contract_accepted'])) {
        $errors['contract_accepted'] = 'Необходимо подтвердить ознакомление с контрактом';
    }
    
    return $errors;
}

// Сохранение данных в Cookies на год (с защитой от XSS через json_encode)
function saveToCookies($data) {
    foreach ($data as $key => $value) {
        if (is_array($value)) {
            // Безопасное преобразование массива в строку
            $value = json_encode($value);
        }
        // Экранирование имени cookie (на всякий случай)
        $cookie_name = 'saved_' . preg_replace('/[^a-zA-Z0-9_]/', '_', $key);
        setcookie($cookie_name, $value, time() + 365*24*60*60, '/', '', false, true);
    }
}

// Загрузка данных из Cookies (с поддержкой JSON)
function loadFromCookies() {
    $data = [];
    foreach ($_COOKIE as $key => $value) {
        if (strpos($key, 'saved_') === 0) {
            $field = substr($key, 6);
            // Пытаемся декодировать JSON (если это массив)
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                $data[$field] = $decoded;
            } else {
                $data[$field] = $value;
            }
        }
    }
    return $data;
}

// Генерация логина и пароля (уже безопасно)
function generateCredentials() {
    $login = 'user_' . bin2hex(random_bytes(4));
    $password = bin2hex(random_bytes(8));
    return ['login' => $login, 'password' => $password];
}
?>
