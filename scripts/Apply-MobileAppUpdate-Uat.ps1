$ErrorActionPreference = 'Stop'
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$apiDirectory = Join-Path $repository 'CompAuthApi'
$baseSettings = Get-Content -LiteralPath (Join-Path $apiDirectory 'appsettings.json') -Raw | ConvertFrom-Json
$stagingSettings = Get-Content -LiteralPath (Join-Path $apiDirectory 'appsettings.Staging.json') -Raw | ConvertFrom-Json
$connection = $stagingSettings.ConnectionStrings.StagingConnection
if (-not $connection) { $connection = $baseSettings.ConnectionStrings.StagingConnection }
$target = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($connection)
if ($target.DataSource -notin @('tcp:10.3.3.11', '10.3.3.11', 'tcp:10.3.3.11,1433', '10.3.3.11,1433') -or
    $target.InitialCatalog -ine 'CompAuthDb') {
    throw 'Refusing to migrate: only UAT 10.3.3.11 / CompAuthDb is authorized.'
}
$target['Connect Timeout'] = 10
$migration = '20261013134302_AddMobileAppUpdatePolicies'
$localMigrations = @(Get-ChildItem -LiteralPath (Join-Path $repository 'CompAuthApi.Data/Migrations') -Filter '*.cs' |
    Where-Object { $_.Name -match '^\d{14}_' -and $_.Name -notmatch '\.Designer\.cs$' } | ForEach-Object { $_.BaseName })
$sql = New-Object System.Data.SqlClient.SqlConnection($target.ConnectionString)
try {
    $sql.Open()
    $command = $sql.CreateCommand()
    $command.CommandText = 'SELECT DB_NAME(), CAST(SERVERPROPERTY(''ServerName'') AS nvarchar(128))'
    $reader = $command.ExecuteReader()
    if (-not $reader.Read() -or [string]$reader[0] -ine 'CompAuthDb') { throw 'Database identity verification failed.' }
    Write-Output ('Verified UAT database: ' + $reader[0] + ' on ' + $reader[1] + ' via ' + $target.DataSource)
    $reader.Close()
    $command.CommandText = 'SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId'
    $reader = $command.ExecuteReader()
    $applied = @()
    while ($reader.Read()) { $applied += [string]$reader[0] }
    $reader.Close()
    if ($migration -in $applied) { Write-Output 'Mobile app update migration is already applied to UAT.'; return }
    $pending = @($localMigrations | Where-Object { $_ -notin $applied })
    if ($pending.Count -ne 1 -or $pending[0] -ne $migration -or @($applied | Where-Object { $_ -notin $localMigrations }).Count -ne 0) {
        throw 'Unexpected migration history. Refusing to apply other migrations.'
    }
} finally { $sql.Dispose() }

# Pin the verified UAT connection in this process; never rely on an inherited production override.
$previousConnection = $env:ConnectionStrings__StagingConnection
$previousEnvironment = $env:ASPNETCORE_ENVIRONMENT
Push-Location $repository
try {
    $env:ConnectionStrings__StagingConnection = $target.ConnectionString
    $env:ASPNETCORE_ENVIRONMENT = 'Staging'
    dotnet ef database update $migration --project CompAuthApi.Data/CompAuthApi.Data.csproj --startup-project CompAuthApi/CompAuthApi.csproj -- --environment Staging
    if ($LASTEXITCODE -ne 0) { throw 'UAT migration failed.' }
} finally {
    $env:ConnectionStrings__StagingConnection = $previousConnection
    $env:ASPNETCORE_ENVIRONMENT = $previousEnvironment
    Pop-Location
}
$sql = New-Object System.Data.SqlClient.SqlConnection($target.ConnectionString)
try {
    $sql.Open()
    $command = $sql.CreateCommand()
    $command.CommandText = 'SELECT Platform, Enabled, MinimumVersion, MinimumBuild, Revision FROM MobileAppUpdatePolicies ORDER BY Platform'
    $reader = $command.ExecuteReader()
    while ($reader.Read()) { Write-Output ('UAT policy: ' + $reader[0] + ', enabled=' + $reader[1] + ', minimum=' + $reader[2] + ', build=' + $reader[3] + ', revision=' + $reader[4]) }
    $reader.Close()
} finally { $sql.Dispose() }
