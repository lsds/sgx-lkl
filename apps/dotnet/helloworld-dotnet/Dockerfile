# FROM mcr.microsoft.com/dotnet/core/runtime:2.2
# COPY ./bin/Release/netcoreapp2.2/publish/ app/
# ENTRYPOINT ["dotnet", "app/HelloWorld.dll"]

FROM mcr.microsoft.com/dotnet/core/sdk:2.2.402-alpine3.9 as builder

WORKDIR /src
COPY *.csproj /src
RUN dotnet restore
COPY . /src
RUN dotnet publish -c Release -o build

FROM mcr.microsoft.com/dotnet/core/runtime:2.2-alpine3.9
WORKDIR /app
COPY --from=builder /src/build ./
ENTRYPOINT ["dotnet", "HelloWorld.dll"]