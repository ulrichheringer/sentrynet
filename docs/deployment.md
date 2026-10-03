# Packaging and operation

## .NET tool

```sh
dotnet pack src/SentryNet.Cli -c Release -o artifacts/packages
dotnet tool install SentryNet.Cli --add-source artifacts/packages --tool-path artifacts/tool
artifacts/tool/sentrynet version
```

This creates a local tool package; it does not publish to NuGet. Installation requires a .NET 8 runtime. A globally installed tool can use the same package with `--global` if desired. NuGet publication is intentionally separate from source publication.

## Native executable

```sh
dotnet publish src/SentryNet.Cli -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/linux-x64
```

Supported build RIDs include `linux-x64`, `linux-arm64`, `win-x64`, `win-arm64`, `osx-x64` and `osx-arm64`. The release workflow builds these as downloadable workflow artifacts; it does not automatically create a GitHub release or upload a NuGet package. Core runtimes and external-tool dependencies need patching even for self-contained distribution. The CI matrix runs the source test suite on all three OS families.

## Docker

```sh
docker build -t sentrynet:local .
docker run --rm sentrynet:local doctor
docker run --rm --mount type=bind,source="$(pwd)/reports",target=/reports sentrynet:local demo --output /reports/demo
```

Create the host output directory first and ensure the non-root container user (UID 1654 on the bundled .NET image) can write it. On PowerShell, use an absolute Windows `source` path for the bind mount. `/reports` is owned by the application user inside the image. The image includes Nmap and dig; their own licenses apply. Review distribution requirements before redistributing the image commercially.

Container loopback is the container, not the host. Network auditing must use the explicitly authorized addresses reachable from the container. Avoid privileged mode. On Linux, host networking can be explicitly selected for an agreed local-network engagement, but is not the default. ICMP may need OS capabilities; failure is reported as a collection gap. Do not grant broad capabilities just to remove a partial status.

## Linux validation from Windows

If a Windows application-control policy blocks xUnit assembly discovery, keep the policy and run a Linux validation container:

```powershell
docker run --rm --mount 'type=bind,source=C:\path\to\sentrynet,target=/work' --workdir /work mcr.microsoft.com/dotnet/sdk:8.0 dotnet test --artifacts-path /tmp/sentrynet-build
```

Separate container build output avoids rewriting Windows `obj`/`bin` restore metadata. A test command reporting zero discovered tests is not a passing validation.
