#!/bin/sh

# dotnet build
# dotnet publish -c Release
# dotnet bin\Debug\netcoreapp2.2\HelloWorld.dll

dotnet publish -r linux-musl-x64 -c Release