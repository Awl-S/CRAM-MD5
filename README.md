
# CRAM-MD5 Authentication Server

Этот сервер на основе Go реализует CRAM-MD5 механизм аутентификации, а также предоставляет простую форму для входа.

## Описание

CRAM-MD5 (Challenge-Response Authentication Mechanism) — это механизм аутентификации, который использует MD5 хэширование для защиты пароля при передаче. Сервер также включает HTML-форму для стандартного ввода имени пользователя и пароля.

### Основные компоненты

- **CRAM-MD5 аутентификация** — использует вызов `generateChallenge` для отправки случайного челенджа клиенту и проверяет ответ клиента с использованием HMAC-MD5 хеширования.
- **loginFormHandler** — отображает HTML форму для входа в систему.
- **authHandler** — обрабатывает запросы авторизации из формы и проверяет учетные данные.

## Структура проекта

1. **`main.go`** — Основной файл с определением обработчиков запросов и логикой CRAM-MD5 сервера.

## Установка

### Требования

- Go 1.18+

### Шаги для установки

1. Клонируйте репозиторий:
    ```bash
    git clone https://github.com/yourcompany/cram-md5-server.git
    ```

2. Перейдите в директорию проекта:
    ```bash
    cd cram-md5-server
    ```

3. Установите зависимости (если требуется):
    ```bash
    go mod tidy
    ```

4. Запустите сервер:
    ```bash
    go run main.go
    ```

Сервер будет доступен по адресу `http://localhost:8080`.

## Использование

### 1. CRAM-MD5 Аутентификация

Для аутентификации с использованием CRAM-MD5 отправьте GET-запрос с заголовком `Authorization`, указанным в формате CRAM-MD5.

- **Шаг 1**: Получите `challenge` от сервера.
- **Шаг 2**: Сформируйте ответ с помощью `generateResponse`, используя полученный `challenge`, `username`, и `password`.
- **Шаг 3**: Отправьте запрос с заголовком `Authorization: CRAM-MD5 <response>`.

Пример запроса:
```bash
curl -H "Authorization: CRAM-MD5 <response>" http://localhost:8080
```

### 2. Стандартная форма для входа

Откройте `http://localhost:8080` в браузере, чтобы отобразить форму входа. Введите имя пользователя и пароль (по умолчанию: `admin` и `password`) и нажмите "Submit".

## Архитектура

### CRAM-MD5 Механизм

Функции `generateChallenge` и `generateResponse` используются для создания случайного `challenge` и вычисления ожидаемого ответа на основе `username` и `password`. Функция `verifyResponse` проверяет полученный ответ с ожидаемым, чтобы подтвердить подлинность запроса.

## Безопасность и развертывание

Для продакшн-среды рекомендуется:

- Переключиться на HTTPS для защиты данных при передаче.
- Учитывать использование более сильного алгоритма хеширования, поскольку MD5 считается устаревшим.

## Лицензия

Этот проект распространяется под лицензией MIT.