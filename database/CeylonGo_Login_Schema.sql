/*
CeylonGo — Login/Identity database bootstrap
Target: Microsoft SQL Server (development database: CeylonGoDB)
Owner: Mithushika (Tourist Login + SQL authentication schema)
Contract: Agreed with Patithijan for initial Login API integration.

Tables:
  dbo.Roles     RoleId INT IDENTITY PK, RoleName NVARCHAR(30) UNIQUE
  dbo.Users     UserId INT IDENTITY PK, Email NVARCHAR(320) case-insensitive UNIQUE,
                PasswordHash NVARCHAR(255), DisplayName NVARCHAR(120),
                IsActive BIT (explicitly specified when account is created),
                CreatedAtUtc DATETIME2 DEFAULT SYSUTCDATETIME()
  dbo.UserRoles UserId INT PK + FK -> Users; RoleId INT FK -> Roles.
                Initial version: one role per user.

Security and integration:
- FastAPI owns password hashing and verification (Argon2id via pwdlib[argon2]
  is proposed; registration owner must confirm compatible configuration).
- Store only the complete encoded password hash. Do not use SQL HASHBYTES.
- Normalize emails in backend by trimming surrounding whitespace and lowercasing.
- Never store raw passwords, JWT signing secrets, or JWTs in these tables.
- Vendor approval status is separate from dbo.Users.IsActive.
- API: POST /api/auth/login; 30-minute bearer access token; no refresh/revocation
  in the initial phase. Verify the backend's latest contract before integration.

Run only against an authorized development database. Review before executing.
Back up any existing database. Existing tables are not dropped or altered.
If a table already exists with a different schema, STOP and plan a migration;
this script does not repair existing tables.
*/

USE [CeylonGoDB];
GO

IF OBJECT_ID(N'dbo.Roles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Roles
    (
        RoleId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
        RoleName NVARCHAR(30) NOT NULL CONSTRAINT UQ_Roles_RoleName UNIQUE
    );
END;
GO

IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users
    (
        UserId INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
        Email NVARCHAR(320) COLLATE Latin1_General_100_CI_AS NOT NULL
            CONSTRAINT UQ_Users_Email UNIQUE,
        PasswordHash NVARCHAR(255) NOT NULL,
        DisplayName NVARCHAR(120) NOT NULL,
        IsActive BIT NOT NULL,
        CreatedAtUtc DATETIME2 NOT NULL
            CONSTRAINT DF_Users_CreatedAtUtc DEFAULT SYSUTCDATETIME()
    );
END;
GO

IF OBJECT_ID(N'dbo.UserRoles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.UserRoles
    (
        UserId INT NOT NULL CONSTRAINT PK_UserRoles PRIMARY KEY,
        RoleId INT NOT NULL,
        CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserId)
            REFERENCES dbo.Users(UserId),
        CONSTRAINT FK_UserRoles_Roles FOREIGN KEY (RoleId)
            REFERENCES dbo.Roles(RoleId)
    );
END;
GO

/* Seed fixed role names only. Do not assume or hardcode RoleId values. */
INSERT INTO dbo.Roles (RoleName)
SELECT v.RoleName
FROM (VALUES (N'Tourist'), (N'Vendor'), (N'Admin')) AS v(RoleName)
WHERE NOT EXISTS
(
    SELECT 1 FROM dbo.Roles AS r WHERE r.RoleName = v.RoleName
);
GO

/* Read-only verification: tables, columns, constraints and roles */
SELECT t.name AS TableName, c.name AS ColumnName, ty.name AS DataType,
       CASE WHEN c.max_length = -1 THEN -1
            WHEN ty.name IN (N'nvarchar', N'nchar') THEN c.max_length / 2
            ELSE c.max_length END AS MaxLength,
       c.is_nullable AS IsNullable, c.is_identity AS IsIdentity,
       c.collation_name AS CollationName, dc.definition AS DefaultValue
FROM sys.tables AS t
JOIN sys.columns AS c ON c.object_id = t.object_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
WHERE SCHEMA_NAME(t.schema_id) = N'dbo'
  AND t.name IN (N'Users', N'Roles', N'UserRoles')
ORDER BY t.name, c.column_id;

SELECT OBJECT_NAME(k.parent_object_id) AS TableName,
       k.name AS ConstraintName, k.type_desc AS ConstraintType
FROM sys.key_constraints AS k
WHERE k.parent_object_id IN (
    OBJECT_ID(N'dbo.Users'), OBJECT_ID(N'dbo.Roles'), OBJECT_ID(N'dbo.UserRoles'))
ORDER BY TableName, ConstraintType;

SELECT fk.name AS ForeignKeyName,
       OBJECT_NAME(fk.parent_object_id) AS ChildTable,
       OBJECT_NAME(fk.referenced_object_id) AS ParentTable
FROM sys.foreign_keys AS fk
WHERE fk.parent_object_id = OBJECT_ID(N'dbo.UserRoles')
ORDER BY fk.name;

SELECT RoleId, RoleName FROM dbo.Roles ORDER BY RoleName;
GO
