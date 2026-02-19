# anonymize-data

Script em Python para **pseudonimizar logs em CSV**, substituindo **e-mails** por identificadores determinísticos e gerando **mapas de usuários e domínios**.

---

## O que o script faz

Dado um CSV de entrada, o script:

1. Varre o arquivo e encontra **e-mails** em qualquer coluna/célula.
2. Gera um mapeamento determinístico (HMAC-SHA256) para:
   - `original_email -> USRxxxxxx@<dominio_anon>`
   - `original_domain -> <dominio_anon>`
3. Grava:
   - `logs_pseudo.csv` (CSV original com e-mails substituídos)
   - `map_users.csv` (tabela: e-mail original, e-mail anon, `user_id`)
   - `map_domains.csv` (tabela: domínio original, domínio anon, passthrough)

---

## Requisitos

- Python 3.9+ (recomendado 3.11+)
- Sem dependências externas (somente biblioteca padrão)

---

## Como usar

### 1) Defina o segredo (obrigatório)

```bash
export LOG_PSEUDO_SECRET="uma-chave-super-secreta-e-longa"
```

### 2) Rode o script

```bash
python3 pseudonymization_data.py ./logs.csv
```

Saída padrão: `<pasta_do_csv>/pseudo_out/`

Arquivos gerados:
- `anon_out/logs_pseudo.csv`
- `anon_out/map_users.csv`
- `anon_out/map_domains.csv`

---

## Exemplos

### Especificar diretório de saída

```bash
python3 pseudonymization_data.py ./logs.csv ./saida_pseudo
```

### Log em arquivo + nível INFO

```bash
python3 pseudonymization_data.py ./logs.csv ./saida_pseudo --log-file ./execucao.log --log-level INFO
```

### Debug (inclui traceback em erros)

```bash
python3 pseudonymization_data.py ./logs.csv --log-level DEBUG
```

### Somente e-mails (não mexer em domínios soltos)

Por padrão, o script também pode substituir domínios “soltos” (tokens como `exemplo.com.br`) **somente** se o domínio existir no `domain_map`.

Se quiser substituir **apenas e-mails completos**:

```bash
python3 pseudonymization_data.py ./logs.csv --no-domain-tokens
```

---

## Passthrough (não anonimizar domínio)

Domínios que permanecem inalterados:

- `admin.google.com`
- `password.google.com`

Ex.: `nome@admin.google.com` → `USR123456@admin.google.com`

---

## Referências

- logging: https://docs.python.org/3/library/logging.html
- csv: https://docs.python.org/3/library/csv.html
- HMAC (RFC 2104): https://www.rfc-editor.org/rfc/rfc2104
- SHA-256 (FIPS 180-4): https://csrc.nist.gov/publications/detail/fips/180/4/final
