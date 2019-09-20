#!/bin/sh

echo "buildenv.sh dotnet core runtime"

set -ex

apk update
apk add iputils iproute2 unzip libstdc++ openjdk8-jre nss

# libssl1.0 (missing)
apk add --no-cache wget
#apk add --no-cache icu-libs wget ca-certificates krb5-libs libgcc libintl libssl1.1 libstdc++ lttng-ust tzdata userspace-rcu zlib

# .NET Core dependencies
apk add --no-cache ca-certificates \
        krb5-libs \
        libgcc \
        libintl \
        libssl1.1 \
        libstdc++6 \
        lttng-ust \
        tzdata \
        userspace-rcu \
        zlib

apk add --no-cache musl-dev

LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
DOTNET_CLI_TELEMETRY_OPTOUT=1
DOTNET_RUNNING_IN_CONTAINER=true
# Set the invariant mode since icu_libs isn't included (see https://github.com/dotnet/announcements/issues/20)
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true

# Install .NET Core
DOTNET_VERSION="2.2.3"

wget -O dotnet.tar.gz https://dotnetcli.blob.core.windows.net/dotnet/Runtime/$DOTNET_VERSION/dotnet-runtime-$DOTNET_VERSION-linux-musl-x64.tar.gz \
    && dotnet_sha512='b11e8731dd2e6b8738fb3a2762ed90de08df6661a8720ed76ef9429b99d763d0913ee100042a2995d72a13b50394a7e357397cecb23402c3104075efda04f62b' \
    && echo "$dotnet_sha512  dotnet.tar.gz" | sha512sum -c - \
    && mkdir -p /usr/share/dotnet \
    && tar -C /usr/share/dotnet -xzf dotnet.tar.gz \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
    && rm dotnet.tar.gz

# Install artifacts credential provider
NUGET_CREDENTIAL_PROVIDER_VERSION="0.1.11"

wget -O microsoft.nuget.credentialprovider.tar.gz https://azureartifactassets.blob.core.windows.net/credentialprovider/releases/download/$NUGET_CREDENTIAL_PROVIDER_VERSION/Microsoft.NetCore2.NuGet.CredentialProvider.tar.gz
credprovider_sha512='a23477b13d5156118eec6241b327ab9f2f1083dba5c647958c5200ea701222b61c28cc3d4ac7b3306f613455f93599227ec263c9ce0cd7abc33e3266f5db10a7'
echo "$credprovider_sha512  microsoft.nuget.credentialprovider.tar.gz" | sha512sum -c -
mkdir -p /usr/share/credentialprovider
tar -C /usr/share/credentialprovider -xzf microsoft.nuget.credentialprovider.tar.gz
rm microsoft.nuget.credentialprovider.tar.gz

