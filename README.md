# SentryNet

[![CI](https://github.com/ulrichheringer/sentrynet/actions/workflows/ci.yml/badge.svg)](https://github.com/ulrichheringer/sentrynet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)

**Auditoria defensiva de redes em .NET 8/C#, com CLI multiplataforma, evidências e relatórios.**

SentryNet ajuda consultorias e equipes de segurança a inventariar ambientes autorizados, revisar configurações e acompanhar mudanças. O projeto é uma versão inicial funcional (0.1), com arquitetura extensível e limitações documentadas. Não executa exploração, tentativas de senha ou correções automáticas.

## Funcionalidades

| Área | Implementado |
| --- | --- |
| Descoberta | Interfaces locais, IPv4/CIDR, IPv6 individual, ICMP opcional e conexões TCP |
| Inventário | Hosts/IPs, portas abertas, serviços inferidos e identificação via Nmap opcional |
| DNS/domínio | A, AAAA, MX, NS, SOA, TXT, CAA e DMARC nativos; integração com dig |
| HTTP | Resposta do caminho raiz, headers, cookies com valores ocultados, CSP, HSTS, CORS e redirecionamentos |
| TLS | Cadeia/confiança, nome, validade, SHA-256, SAN, emissor, chave RSA, assinatura e protocolo negociado |
| Regras | 30 regras nativas, cinco severidades, evidências, recomendações, referências, regras JSON e overrides |
| Histórico | Separação por cliente, identificador de engagement, gravação atômica e comparação de baseline |
| Mudanças | Novos achados, serviços, versões, certificados e registros DNS; TTL não gera mudança |
| Relatórios | JSON versionado, HTML responsivo/imprimível e SARIF 2.1.0 |
| Operação | DI, async, concorrência limitada, timeout, intervalo por probe, deadline, Ctrl+C e códigos de saída |
| Extensão | Plugins explícitos via DLL e contratos para futura distribuição de scans |

## Começar

Requer SDK .NET 8 atualizado. Nmap e dig são opcionais; os scanners nativos funcionam sem eles.

```sh
git clone https://github.com/ulrichheringer/sentrynet.git
cd sentrynet
dotnet build -c Release
dotnet test -c Release
dotnet run --project src/SentryNet.Cli -- help
```

Gere um relatório **sintético, sem rede**:

```sh
dotnet run --project src/SentryNet.Cli -- demo --output reports/demo --formats json,html,sarif
```

Abra `reports/demo.html` no navegador. O relatório traz resumo executivo, severidades, inventário, evidências, recomendações, metodologia e lacunas de coleta.

Para empacotar e instalar como ferramenta local:

```sh
dotnet pack src/SentryNet.Cli -c Release -o artifacts/packages
dotnet tool install SentryNet.Cli --add-source artifacts/packages --tool-path artifacts/tool
artifacts/tool/sentrynet help
```

No Windows, execute `artifacts/tool/sentrynet.exe`. Também é possível usar `dotnet publish` ou a imagem Docker descrita em [deployment](docs/deployment.md).

## Autorização e escopo

Toda execução ativa exige `--authorized`, uma referência de autorização e `--scope` explícito. O marcador registra a declaração do operador; SentryNet não verifica documentos de autorização.

O exemplo abaixo opera apenas no loopback do próprio computador:

```sh
dotnet run --project src/SentryNet.Cli -- scan --targets 127.0.0.1 --scope 127.0.0.1 --authorized --authorization-ref "Meu ambiente local" --profile quick --output reports/local
```

Use alvos de sua propriedade ou com autorização expressa. Antes de uma auditoria, revise o plano offline:

```sh
dotnet run --project src/SentryNet.Cli -- plan --targets 192.0.2.0/28 --scope 192.0.2.0/28 --profile standard
```

`192.0.2.0/24` é usado apenas como exemplo de documentação. Substitua pelos alvos e escopo do contrato antes de um scan ativo. O plano não resolve DNS nem envia probes; a resolução e o limite global de endereços são conferidos na execução.

Nomes devem estar explicitamente no escopo. Um hostname autorizado permite os IPs retornados pelo resolver no início; conexões usam esses IPs fixos e preservam Host/SNI. Uma autorização apenas por CIDR aceita alvos IP, mas não permite consultar nomes arbitrários. Não há wildcard de domínio, descoberta de subdomínios ou seguimento automático de redirects. Queries de DNS usam a infraestrutura DNS configurada e incluem `_dmarc` do nome autorizado. Consulte [o modelo de segurança](docs/security-model.md).

## Comandos e configuração

```sh
# Inventário local, sem probes de rede
dotnet run --project src/SentryNet.Cli -- inventory
dotnet run --project src/SentryNet.Cli -- doctor
dotnet run --project src/SentryNet.Cli -- rules

# Gerar configuração (não sobrescreve arquivo existente)
dotnet run --project src/SentryNet.Cli -- init --output sentrynet.json

# CLI substitui os defaults do arquivo; autorização deve ser repetida por execução
dotnet run --project src/SentryNet.Cli -- scan --config samples/local.json --authorized --authorization-ref "Meu ambiente local" --client laboratorio --engagement revisao-001 --output reports/laboratorio

# Consultar e comparar histórico
dotnet run --project src/SentryNet.Cli -- history --client laboratorio
dotnet run --project src/SentryNet.Cli -- diff --baseline reports/antes.json --current reports/depois.json --output reports/mudancas.json
dotnet run --project src/SentryNet.Cli -- report --input reports/depois.json --baseline reports/antes.json --output reports/comparativo --formats html,sarif
```

Opções adicionais:

* `--targets-file`: um alvo por linha, com comentários iniciados por `#`.
* `--ports 22,80,443,8000-8010`: seleção e intervalos; máximo de 4.096 portas.
* `--scanners dns,ping,tcp,http,tls,nmap,dig`: scanners escolhidos explicitamente.
* `--http-ports` e `--tls-ports`: mapeiam serviços em portas não convencionais; somente portas incluídas também em `--ports` serão usadas. Uma porta HTTP presente em `--tls-ports` usa HTTPS.
* `--dns-server 10.0.0.53 --dns-port 53`: resolver para análise de registros; a resolução inicial de alvos usa o resolver do sistema.
* `--parallelism`, `--timeout-ms`, `--delay-ms`, `--max-hosts`, `--max-duration`: limites operacionais.
* `--rules-file samples/rules.json`, `--disable-rules HTTP003,NET003`, `--severity NET003=Low`: política de achados.
* `--baseline FILE`: inclui comparação no HTML e escreve `PREFIX.diff.json`.
* `--plugin PATH.dll`: carrega código confiável explicitamente; veja [plugins](docs/plugins.md).
* `--json`: relatório JSON em stdout; mensagens operacionais ficam em stderr.
* `--fail-on High`: sinaliza o limiar de severidade para automações.

Os perfis são `quick` (DNS/TCP, 5 portas), `standard` (DNS/TCP/HTTP/TLS, portas padrão) e `full` (acrescenta ICMP, dig e Nmap). `full` não significa varrer todas as portas. Nmap e dig devem estar no PATH. Nenhum scanner é instalado automaticamente pela CLI.

| Código | Significado |
| --- | --- |
| 0 | Coleta concluída; limiar não atingido |
| 1 | Erro de entrada, arquivo ou operação |
| 2 | Coleta concluída com achados no limiar configurado |
| 3 | Coleta parcial, incluindo probes falhos ou pulados; precede o limiar |
| 130 | Cancelamento ou deadline; não salva um scan interrompido como concluído |

O histórico fica em `LocalApplicationData/SentryNet/history`, separado por hash do nome do cliente; `--history-dir` altera a raiz. Isso organiza arquivos, mas **não fornece isolamento de segurança entre tenants**. Arquivos JSON/HTML contêm dados de auditoria; aplique os controles de acesso e retenção do engagement. JSON completo guarda todas as evidências; HTML detalha evidências dos achados e a cobertura de cada scanner.

## Qualidade e extensibilidade

O núcleo não depende da CLI nem de bibliotecas de rede. Scanners implementam `IScanner`; regras implementam `IRule`. Plugins implementam `ISentryNetPlugin` e só são carregados por uma opção explícita. Interfaces de storage e dispatcher permitem evoluir para API, agentes e dashboard, sem habilitar execução remota nesta versão.

Há testes de autorização, limites, CIDR/IPv6, regras, baseline, serialização, sanitização HTML, parsing Nmap/dig, DNS UDP e servidores HTTP/TLS locais, além da CLI em processo separado. CI executa build e testes em Windows, Linux e macOS. Nenhum teste precisa de acesso a alvos externos.

Detalhes: [arquitetura](docs/architecture.md), [limitações](docs/limitations.md), [modelo de segurança](docs/security-model.md), [deployment](docs/deployment.md) e [roadmap](docs/roadmap.md).

.NET 8 foi mantido conforme o objetivo inicial; seu suporte termina em **10 de novembro de 2026**. A migração de runtime consta no roadmap. [Política oficial da Microsoft](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).

## Contribuir e licença

Leia [CONTRIBUTING.md](CONTRIBUTING.md) e [SECURITY.md](SECURITY.md). MIT, com licenças de dependências preservadas. Nmap e dig são processos externos opcionais; suas licenças continuam aplicáveis, inclusive à distribuição em containers.
