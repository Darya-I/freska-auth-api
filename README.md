# Auth API

����������� ��� �������������� � ����������� �������������.

## ��������

���� ����������� ������������� API ��� �����������, �������������� � ������������� ����������� ����� �������������.

## �������� �������

- *�����������*: ��������� ����� ������������� ������������������ � ������ ��� ��� ����� ������� ������.
- *�����������*: ��������� ������������� ������������������� � �������� JWT-�����.
- *������������� ����������� �����*: ���������� ������������� ������ � �������������� �������.
- *�������� Email*: ���������� ������� API ��� �������� email-���������.

## ����������

- .NET 6.0 (��� ����)
- ���� ������ (��������, SQL Server, PostgreSQL � �.�.)
- SMTP-������ ��� �������� email-��������� (������������ Mailopost API)


## �������������

### �����

#### POST /api/auth/Registration
������������ ������ ������������.

*���� �������:*
{
    "Email": "user@example.com",
    "Password": "password123!"
}

*�����:*
- �����: 200 OK
- ������: 400 Bad Request

#### POST /api/auth/Authenticate
��������������� ������������ � ����� JWT-�����.

*���� �������:*
json
{
    "Email": "user@example.com",
    "Password": "password123!"
}

*�����:*
- �����: 200 OK � JWT-�������
- ������: 401 Unauthorized

#### GET /api/auth/ConfirmEmail
������������ ����������� ����� ������������.

*��������� �������:*
- userId - ID ������������
- code - ����� �������������

*�����:*
- �����: 200 OK
- ������: 400 Bad Request

## ������������ JWT

������������ JWT ������ ��������� � appsettings.json. ������ ���������:
json
{
  "JwtConfig": {
    "Secret": "YOUR_SECRET_KEY"
  },
  "EmailConfig": {
    "API_KEY": "YOUR_MAILOPOST_API_KEY"
  }
}

## ��������� CORS

� ������� ��������� �������� CORS, ������� ��������� ������� � ������������ ����������.

������ ��������� � Program.cs:
csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin",
        builder => builder.WithOrigins("https://localhost:7036")
        .AllowAnyMethod()
        .AllowAnyHeader()
        );
});