# Auth API

Микросервис для аутентификации и авторизации пользователей.

## Описание

Этот микросервис предоставляет API для регистрации, аутентификации и подтверждения электронной почты пользователей.

## Основные функции

- *Регистрация*: Позволяет новым пользователям зарегистрироваться и создаёт для них новую учётную запись.
- *Авторизация*: Позволяет пользователям аутентифицироваться и получать JWT-токен.
- *Подтверждение электронной почты*: Отправляет пользователям письмо с подтверждающей ссылкой.
- *Отправка Email*: Использует внешнее API для отправки email-сообщений.

## Требования

- .NET 6.0 (или выше)
- База данных (например, SQL Server, PostgreSQL и т.д.)
- SMTP-сервер для отправки email-сообщений (используется Mailopost API)


## Использование

### Роуты

#### POST /api/auth/Registration
Регистрирует нового пользователя.

*Тело запроса:*
{
    "Email": "user@example.com",
    "Password": "password123!"
}

*Ответ:*
- Успех: 200 OK
- Ошибка: 400 Bad Request

#### POST /api/auth/Authenticate
Аутентифицирует пользователя и выдаёт JWT-токен.

*Тело запроса:*
json
{
    "Email": "user@example.com",
    "Password": "password123!"
}

*Ответ:*
- Успех: 200 OK с JWT-токеном
- Ошибка: 401 Unauthorized

#### GET /api/auth/ConfirmEmail
Подтверждает электронную почту пользователя.

*Параметры запроса:*
- userId - ID пользователя
- code - Токен подтверждения

*Ответ:*
- Успех: 200 OK
- Ошибка: 400 Bad Request

## Конфигурация JWT

Конфигурация JWT токена находится в appsettings.json. Пример структуры:
json
{
  "JwtConfig": {
    "Secret": "YOUR_SECRET_KEY"
  },
  "EmailConfig": {
    "API_KEY": "YOUR_MAILOPOST_API_KEY"
  }
}

## Настройка CORS

В проекте настроена политика CORS, которая разрешает запросы с определенных источников.

Пример настройки в Program.cs:
csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        builder => builder.WithOrigins("https://localhost:7036")
        .AllowAnyMethod()
        .AllowAnyHeader()
        );
});