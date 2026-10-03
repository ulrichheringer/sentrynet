#!/bin/sh
set -eu

dotnet test -c Release --artifacts-path /tmp/sentrynet-build --logger 'console;verbosity=minimal'
dotnet pack src/SentryNet.Cli -c Release --artifacts-path /tmp/sentrynet-build -o /tmp/sentrynet-packages
dotnet tool install SentryNet.Cli --add-source /tmp/sentrynet-packages --tool-path /tmp/sentrynet-tool
/tmp/sentrynet-tool/sentrynet version
/tmp/sentrynet-tool/sentrynet demo --output /tmp/sentrynet-demo --formats json,html,sarif
dotnet build samples/SentryNet.SamplePlugin -c Release --artifacts-path /tmp/sentrynet-build
dotnet /tmp/sentrynet-build/bin/SentryNet.Cli/release/SentryNet.Cli.dll plan --config samples/local.json --plugin /tmp/sentrynet-build/bin/SentryNet.SamplePlugin/release/SentryNet.SamplePlugin.dll
