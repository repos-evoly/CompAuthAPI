# Run dotnet command 1
dotnet ef --project ../CompAuthApi.Data/CompAuthApi.Data.csproj database drop
echo "Command 1 completed dropping the database."

# Run dotnet command 2
dotnet ef --project ../CompAuthApi.Data/CompAuthApi.Data.csproj migrations remove
echo "Command 2 completed, removing migrations."

# Run dotnet command 3
dotnet ef --project ../CompAuthApi.Data/CompAuthApi.Data.csproj migrations add InitialCreate
echo "Command 3 completed, adding the InitialCreate."

# Run dotnet command 4
dotnet ef --project ../CompAuthApi.Data/CompAuthApi.Data.csproj database update
echo "Command 4 completed, updating the Database."

# Run dotnet command 5
dotnet run seeddata
echo "Command 5 completed, seeding the Database."