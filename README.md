# CloakSee

Ferramenta web de triagem que detecta **cloaking** em sites: quando a página se comporta diferente conforme o visitante. É o padrão clássico de malware de WordPress. O site redireciona só quem acessa pelo celular, injeta código só para desktop, ou finge estar limpo para o Googlebot.

Você cola uma URL. O CloakSee busca essa URL com 9 perfis de User-Agent em paralelo e repete o acesso simulando 8 origens de clique (Google, WhatsApp, Instagram e outras redes). Ele registra a cadeia de redirecionamentos de cada acesso, cruza as respostas entre si e aplica assinaturas de malware e ofuscação no HTML recebido. O resultado é um relatório com veredito, achados por severidade e evidência, com export em Markdown pronto para colar em chamado.

Irmão do [LinkSee](https://github.com/junglivre/LinkSee): mesma arquitetura (`server.py` single-file, stdlib puro, zero dependências, sem build step).

## Rodar

```sh
git clone <este-repo>
cd cloaksee
python3 server.py
```

Abra `http://127.0.0.1:8791`, cole a URL suspeita e clique em **Analisar site**.

## Perfis de User-Agent

Cada scan visita a mesma URL com 9 identidades diferentes. O malware que esconde comportamento por visitante aparece na comparação entre elas.

| Perfil | Categoria | Por que existe |
|---|---|---|
| Chrome · Windows | browser | Baseline desktop |
| Firefox · Windows | browser | Segundo navegador desktop |
| Safari · macOS | browser | Terceiro navegador desktop |
| Chrome · Android | browser | Alvo clássico de redirect mobile |
| Safari · iPhone | browser | Segundo perfil mobile |
| Googlebot | bot | Malware costuma "se comportar" para crawler (SEO poisoning) |
| Bingbot | bot | Segundo bot, mesma lógica |
| curl | tool | Cliente mínimo; gateways de malware às vezes vazam comportamento |
| PowerShell · Windows | tool | `WindowsPowerShell/5.1` é vetor clássico de download de payload |

## Métodos de análise

**1. Cadeia de redirecionamentos hop a hop.** Cada perfil segue redirects manualmente e registra cada salto (status + Location). Redirect que sai do domínio original vira achado high; `Location:` com scheme `javascript:` ou `data:` vira critical.

**2. Comparação entre perfis.** Depois do fetch, o scanner cruza as 9 respostas:

| Verificação | Severidade |
|---|---|
| URL final diverge para **outro domínio** | high |
| URL final diverge no mesmo domínio | medium |
| Status HTTP diverge entre navegadores | medium |
| Conteúdo divergente (similaridade abaixo de 0.90) | medium; high se abaixo de 0.70 |
| Script carregado só para um perfil | medium; high se `.php`, TLD de risco ou domínio externo |
| Cadeia de redirect cruza domínio externo | high |

**3. Similaridade de shingles (não hash exato).** Sites reais mudam o HTML a cada request: nonce de formulário, timestamp de cache plugin, cache-buster `?_=`. Hash exato acusava divergência onde não havia. O scanner normaliza esse ruído, tokeniza o HTML e compara conjuntos de shingles de 8 tokens (Jaccard) contra o baseline. Um nonce muda meia dúzia de shingles; uma página diferente muda o conjunto inteiro.

**4. Assinaturas no HTML/JS.** Aplicadas ao body de cada perfil:

| Achado | Severidade |
|---|---|
| Redirect para scheme `javascript:`/`data:` | critical |
| `<script src>` em `data:` URI | critical |
| Iframe oculto (`display:none`, 1×1) para domínio externo | high |
| `eval(atob(...))`, `document.write(unescape(...))` | high |
| Blobs `String.fromCharCode` e payload base64 inline | high |
| `<meta refresh>` para domínio externo | high |
| Script servido de arquivo `.php` | high |
| Keywords de famílias conhecidas (wp-vcd, coinhive etc.) | high |
| Blob longo de alta entropia, escapes `\xNN` | medium |
| `location.href/replace` para domínio externo | medium |
| Script de domínio com TLD de risco | medium |

**5. Neutralização anti-ruído.** WAFs bloqueiam bots e tools por padrão. Se Googlebot, Bingbot, curl ou PowerShell receberem 403/429/503 ou falharem, o scanner os marca como **neutros**: saem das comparações de divergência e aparecem esmaecidos no relatório. Bloquear bot é hardening normal, não cloaking. Divergência em perfil de navegador sempre conta.

**6. Detecção por origem (Referer).** Malware também faz cloaking por origem: o site fica limpo para acesso direto e redireciona quem clicou num link do Google ou de rede social. Cada scan repete o acesso com 8 Referers diferentes usando Chrome desktop e Chrome Android, e compara com o mesmo perfil sem Referer:

| Origem | Referer enviado |
|---|---|
| Google | `google.com/search` |
| Bing | `bing.com/search` |
| WhatsApp | `l.whatsapp.com` |
| Instagram | `l.instagram.com` |
| YouTube | `youtube.com` |
| Facebook | `l.facebook.com` |
| X/Twitter | `t.co` |
| TikTok | `tiktok.com` |

Divergência de URL final para outro domínio vira achado high; mudança de conteúdo, status ou scripts exclusivos por origem também viram achados. A lista fica editável em `REFERERS` no topo do `server.py`.

## Entendendo o relatório

O veredito vem do achado mais severo:

| Veredito | Condição |
|---|---|
| `ALERTA` | algum achado critical |
| `SUSPEITO` | algum achado high |
| `ATENÇÃO` | algum achado medium |
| `OK` | nenhum achado |

O relatório mostra, em ordem: banner de veredito com contadores, tabela dos 9 perfis (URL final, status, bytes, hops, título; células divergentes do baseline em destaque), cadeias de redirecionamento, achados com evidência e os agentes afetados, scripts exclusivos por perfil, e um **export Markdown** pronto para colar em chamado. O JSON bruto fica disponível para debug.

Todo achado carrega a evidência (trecho do HTML, URL, cadeia). O veredito é insumo para o analista, não sentença: sites legítimos usam `atob` e geo-redirects.

## Configuração

As opções ficam no topo do `server.py`:

```py
SERVER_PORT = 8791
PASSWORD_PROTECTED = 0
ACCESS_PASSWORD = ""
ALLOW_PRIVATE_HOSTS = 0
```

`PASSWORD_PROTECTED = 1` exige senha (troque `ACCESS_PASSWORD` antes).

`ALLOW_PRIVATE_HOSTS = 1` (ou env `CLOAKSEE_ALLOW_PRIVATE_HOSTS=1`) libera scan de staging interno e localhost. Por padrão IPs privados e hosts locais são bloqueados (guarda anti-SSRF, aplicada também a cada hop de redirecionamento).

Também dá para configurar sem editar o código: crie um arquivo `.env` na pasta do projeto (está no `.gitignore`):

```sh
SERVER_PORT=8791
PASSWORD_PROTECTED=1
ACCESS_PASSWORD=senha
CLOAKSEE_ALLOW_PRIVATE_HOSTS=0
```

Precedência: variável de ambiente > `.env` > default no `server.py`.

## Estender sem programar

No topo do `server.py`:

- `USER_AGENTS`: adicionar ou remover perfis (dict com `id`, `label`, `category`, `ua`)
- `MALWARE_KEYWORDS`: novas keywords de famílias de malware (case-insensitive)
- `RISK_TLDS`: TLDs considerados de risco
- `SIMILARITY_SAME`, `SIMILARITY_LOW`: thresholds de divergência de conteúdo
- `MAX_REDIRECTS`, `TIMEOUT_SECONDS`, `MAX_BYTES`: limites de coleta

## Limitações

- Não executa o JavaScript do alvo. Redirect ou injection que só ocorre via JS no cliente não aparece, mas as assinaturas estáticas pegam `location.href` explícito e ofuscação no código.
- Cloaking por IP ou geolocalização não é coberto. Cloaking por Referer cobre as 8 origens da lista `REFERERS`.
- Analisa só a URL informada, sem autenticação e sem varrer subpáginas.
- Páginas muito pequenas com vários valores dinâmicos podem gerar `content-divergent` medium; a evidência mostra a similaridade para você julgar.

Ver `PLANO.md` para a especificação completa e o roadmap (histórico com diff temporal, Playwright headless, VirusTotal/URLhaus).
