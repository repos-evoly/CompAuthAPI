BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    ALTER TABLE [Settings] ADD [MobileAccessPolicyUpdatedAt] datetimeoffset NULL;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    ALTER TABLE [Settings] ADD [MobileAccessPolicyUpdatedBy] nvarchar(max) NULL;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    ALTER TABLE [Settings] ADD [MobileAccessPolicyVersion] int NOT NULL DEFAULT 1;
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    ALTER TABLE [Settings] ADD [RequireApprovedMobileDevice] bit NOT NULL DEFAULT CAST(1 AS bit);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    ALTER TABLE [DeviceSessions] ADD [ApprovedDeviceAuthenticated] bit NOT NULL DEFAULT CAST(1 AS bit);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922080045_AddDynamicMobileApprovalPolicy'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260922080045_AddDynamicMobileApprovalPolicy', N'8.0.3');
END;
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922111746_AddCompanyMobileAccessPolicies'
)
BEGIN
    CREATE TABLE [CompanyMobileAccessPolicies] (
        [CompanyCode] nvarchar(100) NOT NULL,
        [RequireApprovedDevice] bit NOT NULL,
        [PolicyVersion] int NOT NULL,
        [UpdatedByAuthUserId] int NOT NULL,
        [UpdatedAt] datetimeoffset NOT NULL,
        CONSTRAINT [PK_CompanyMobileAccessPolicies] PRIMARY KEY ([CompanyCode])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260922111746_AddCompanyMobileAccessPolicies'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260922111746_AddCompanyMobileAccessPolicies', N'8.0.3');
END;
GO

COMMIT;
GO

