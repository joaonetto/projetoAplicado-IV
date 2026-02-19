# GeoIP Enrichment (GeoLite2 MMDB + ipgeolocation.io fallback)

Este projeto enriquece logs (CSV) com informações de geolocalização a partir de um **endereço IP** usando:

1. **MaxMind GeoLite2 City (arquivo `.mmdb`)** como fonte primária (offline);  
2. **ipgeolocation.io (API v3)** como *fallback* **somente quando** o `.mmdb` não retorna todos os campos necessários, respeitando o limite diário (ex.: **1000 requisições/dia** no plano free).

O script também oferece um modo **“resume”** para continuar o enriquecimento dos registros faltantes em execuções futuras (por exemplo, no dia seguinte, quando o limite diário da API resetar).


---

## Objetivos

- Enriquecer um CSV (ex.: `logs_anon.csv`) usando a coluna **`Endereço IP`** (ou outra definida via `--ip-col`);
- Adicionar ao final do CSV as colunas:
  - `cidade`
  - `estado`
  - `país`
  - `país ISO`
  - `accuracy_radius_km`
  - `latitude`
  - `longitude`
- Manter **padronização em inglês** nas bases (MMDB e API), para consistência entre fontes;
- Registrar:
  - **cache por IP** (para evitar chamadas repetidas),
  - **contador diário** da API,
  - **eventos em JSONL** (auditoria),
  - **faltantes em CSV** (continuidade).
- Suportar **IPv4 e IPv6**.

---

## Estrutura de arquivos gerados

Ao rodar, o script pode criar:

- **CSV enriquecido** (ex.: `saida_enriquecida.csv`)
- **CSV de faltantes** (ex.: `faltantes.csv`)
- **Cache e controle de uso da API** (por padrão em `.geo_cache/`)
  - `.geo_cache/ip_cache/<ip>.json` (cache por IP)
  - `.geo_cache/ipgeo_usage_YYYY-MM-DD.json` (contador diário)
- **Log de eventos em JSONL** (por padrão `geo_enrichment_events.jsonl`)
- **Logs do console e/ou arquivo** (ex.: `execucao.log`, `resume.log`)

---

## Pré-requisitos

- Python **3.11+** recomendado
- Um arquivo `GeoLite2-City.mmdb` (MaxMind GeoLite2 City)
- (Opcional) API Key do ipgeolocation.io para fallback quando necessário

### Dependências

```bash
pip install geoip2 requests
```

---

## Como obter o GeoLite2 `.mmdb`

Você precisa do arquivo **GeoLite2-City.mmdb** (GeoLite2 City).  
Normalmente o download exige conta na MaxMind e aceite de licença (EULA). Após baixar, coloque o arquivo no diretório do projeto, por exemplo:

```
./GeoLite2-City.mmdb
```

---

## Variáveis de ambiente (recomendado)

Para evitar expor a chave no terminal:

```bash
export IPGEOLOCATION_API_KEY="SUA_CHAVE_AQUI"
```

Você também pode passar a chave diretamente via `--ipgeo-key`, mas não é recomendado em ambientes compartilhados.

---

## Uso do script

O script possui **3 modos** principais:

1. Consultar um IP pontual: `--ip`
2. Enriquecer todo um CSV: `--enrich-all`
3. Continuar/enriquecer apenas faltantes: `--resume-missing`

> Em todos os modos, a ordem de decisão é:
> **Cache (completo) → MMDB → API (somente se MMDB estiver incompleto e dentro do limite diário)**

---

## 1) Consultar um IP específico (retorna na tela)

### IPv4

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --ip 91.128.103.196 \
  --log-level INFO
```

### IPv6

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --ip 2001:4860:4860::8888 \
  --log-level INFO
```

> Se o MMDB não trouxer todos os campos, o script tenta a API (se houver chave e ainda não atingiu o limite diário).

---

## 2) Primeira execução: enriquecer o CSV inteiro

Exemplo (gera `saida_enriquecida.csv` e `faltantes.csv`):

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --enrich-all \
  --input ./logs_anon.csv \
  --output ./saida_enriquecida.csv \
  --missing-csv ./faltantes.csv \
  --log-file ./execucao.log \
  --progress-every 2000
```

### Mudando o nome da coluna de IP

Se o seu CSV não tiver `Endereço IP`:

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --enrich-all \
  --input ./logs_anon.csv \
  --output ./saida_enriquecida.csv \
  --missing-csv ./faltantes.csv \
  --ip-col "IP"
```

### Ajustando encoding (quando CSV vem do Excel)

Se necessário:

```bash
python3 ip.py ... --encoding latin-1
```

---

## 3) Continuar: modo “resume” para preencher faltantes

Quando você bater o limite diário da API, o script registra o que sobrou em `faltantes.csv`.
No dia seguinte, rode o resume para tentar completar:

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --resume-missing \
  --enriched-in ./saida_enriquecida.csv \
  --missing-in ./faltantes.csv \
  --enriched-out ./saida_enriquecida_v2.csv \
  --missing-out ./faltantes_v2.csv \
  --log-file ./resume.log \
  --progress-every 1000
```

- Se ainda faltar (por limite/erro/dados inexistentes), o script gera um novo `faltantes_v2.csv`.
- Para continuar depois, repita usando a última versão gerada:

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --resume-missing \
  --enriched-in ./saida_enriquecida_v2.csv \
  --missing-in ./faltantes_v2.csv \
  --enriched-out ./saida_enriquecida_v3.csv \
  --missing-out ./faltantes_v3.csv
```

---

## Remover a coluna “Endereço IP” do CSV de saída

Se você deseja que o relatório final **não inclua** a coluna de IP (mas o script ainda lê o IP para enriquecer), use `--drop-ip-col`.

### Enrich-all sem “Endereço IP” no output

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --enrich-all \
  --input ./logs_anon.csv \
  --output ./saida_enriquecida.csv \
  --missing-csv ./faltantes.csv \
  --drop-ip-col
```

### Resume-missing sem “Endereço IP” no output

```bash
python3 ip.py \
  --mmdb ./GeoLite2-City.mmdb \
  --resume-missing \
  --enriched-in ./saida_enriquecida.csv \
  --missing-in ./faltantes.csv \
  --enriched-out ./saida_enriquecida_v2.csv \
  --missing-out ./faltantes_v2.csv \
  --drop-ip-col
```

---

## Logs e acompanhamento de execução

### Log no console

Por padrão, logs saem no console.

### Log em arquivo

```bash
python3 ip.py ... --log-file ./execucao.log
```

### Nível de log

- `INFO` (padrão) — recomendado
- `DEBUG` — detalhado (cache, decisões, etc.)

```bash
python3 ip.py ... --log-level DEBUG --log-file ./debug.log
```

### progress-every

`--progress-every N` escreve um checkpoint a cada **N linhas** no modo CSV (ex.: `2000`).  
Para desativar, use `--progress-every 0`.

---

## Sobre a API do ipgeolocation.io (plano free)

- Limite típico: **1000 requisições/dia** (pode variar conforme o plano)
- O plano free não suporta `lang=pt` — usamos `lang=en` por padrão.
- Quando o limite diário é atingido, o script:
  - para de tentar a API,
  - registra o erro,
  - mantém o registro como faltante no CSV de faltantes.

---

## Saída e auditoria

O CSV enriquecido inclui duas colunas de auditoria:

- `__geo_source` — de onde veio o dado (`mmdb`, `cache`, `ipgeolocation`, `limit_hit`, etc.)
- `__geo_error` — descrição de erro (se existir)

Além disso, `geo_enrichment_events.jsonl` registra cada evento de lookup (útil para auditoria).

---

## Troubleshooting

### “MMDB not found”
Verifique o caminho do arquivo:

```bash
--mmdb ./GeoLite2-City.mmdb
```

### “Column not found: Endereço IP”
Use `--ip-col` com o nome correto da coluna no CSV:

```bash
--ip-col "IP"
```

### Erros de CSV (delimitador / encoding)
- O script tenta detectar `;` vs `,` automaticamente.
- Se tiver caracteres estranhos, tente:

```bash
--encoding latin-1
```

### Limite da API atingido
- Rode o script novamente no dia seguinte usando `--resume-missing`.

---

## Licenças e responsabilidade

- GeoLite2/MMDB possui termos de uso da MaxMind.
- ipgeolocation.io possui termos e limites conforme o plano.
- ChronoSec sobre [Apache Version 2.0](https://github.com/joaonetto/projetoAplicado-IV/blob/main/LICENSE)
