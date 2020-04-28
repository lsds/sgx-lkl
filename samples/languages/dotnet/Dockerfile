# Build the application using the DotNet SDK (from Ubuntu)
FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic as builder
WORKDIR /src
COPY ./HelloWorld /src
RUN dotnet restore
RUN dotnet publish -r linux-musl-x64 -c Release -o build

# Bundle the application with the CoreCLR runtime (from Alpine)
FROM mcr.microsoft.com/dotnet/core/runtime:3.0.0-alpine3.9
RUN mkdir -p /app
WORKDIR /app
COPY --from=builder /src/build ./
ENTRYPOINT [ "/usr/bin/dotnet", "HelloWorld.dll" ]
