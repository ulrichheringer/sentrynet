FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /source
COPY . .
RUN dotnet publish src/SentryNet.Cli -c Release --no-self-contained -o /app/publish

FROM mcr.microsoft.com/dotnet/runtime:8.0-bookworm-slim
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir /reports && chown app:app /reports
USER app
ENV HOME=/home/app
ENTRYPOINT ["dotnet", "SentryNet.Cli.dll"]
CMD ["help"]
