---
name: security-review
version: 1.0.0
author: Hermes Agent
description: Roteiro para revisar segurança de PRs e código sensível.
platforms: [linux, macos, windows]
metadata:
  hermes:
    category: security
    tags: [appsec, review, mitre, owasp]
---

# Skill: Revisão de Segurança de Aplicação

Roteiro pronto para revisão de segurança de PRs, code review e análise de código sensível.
Aplica-se a backend, APIs, login, autenticação, bancos de dados e integrações com terceiros.

## Quando usar

- Revisão de qualquer PR que modifique login, senha, permissões, autenticação, bearer token,
  arquivo de config, banco de dados ou entrada de usuário.
- Auditoria de código legado ou de terceiros.
- Quando alguém reportar uma vulnerabilidade e pedir análise.

## Como executar

1. Leia o código modificado com `read_file`/`search_files`. Verifique chamadas de função,
   fluxos de erro e estado mutável.
2. Verifique cada categoria da checklist abaixo. Marque "OK" quando nada for encontrado.
3. Mapeie MITRE ATT&CK para falhas críticas (veja template abaixo).
4. Teste comportamental — rode o fluxo comprometido (login, tokens, etc.) e confirme o resultado.
5. Relate: tabela de achados, prioridade, MITRE ID e correção sugerida.

## Checklist de revisão

### Autenticação e sessão

- [ ] Senhas são salvos como hash (bcrypt/argon2/PBKDF2), nunca em texto puro?
- [ ] Comparação de senha usa `secrets.compare_digest` (tempo constante) para evitar timing attack?
- [ ] Senha nunca é injetada no SQL — usa parâmetros vinculados (`?`) ou ORM?
- [ ] Busca pelo usuário no SQL retorna apenas o usuário (não a senha)?
- [ ] Não há taxa limitação de tentativas ou lockout de conta?
- [ ] Login não aceita credenciais vazias ou nulas?

### Entrada e saída

- [ ] Entrada de usuário é validada antes do uso (tipo, comprimento, formato)?
- [ ] Parâmetros no SQL usam `?` placeholders (não f-string/concatenação)?
- [ ] Output não expõe stack trace ou erros internos?
- [ ] Path traversal impossível (sem `../` ou `..\\` em caminhos do usuário)?

### Dados sensíveis

- [ ] Senhas, tokens, chaves JWT são hasheados/assinados corretamente?
- [ ] JWT usa secret/RS256, não a versão insegura `none`?
- [ ] Cookies de sessão têm `HttpOnly`, `Secure`, `SameSite` definidos?
- [ ] Arquivos de dados (SQLite, JSON, CSV) não expõem dados sensíveis?

### Configuração e dependências

- [ ] `.env` não é versionado — `git check-ignore .env*` / `git ls-files .env`?
- [ ] Dependências sem vulnerabilidades conhecidas (check `pip audit` / `safety`)?
- [ ] Sem chaves API/secret hardcoded em código-fonte?
- [ ] Headers de segurança ausentes (CSP, X-Content-Type-Options, HSTS)?

### Lógica de negócio

- [ ] Permissões de acesso são verificadas em cada endpoint/serviço?
- [ ] Sem Bypass de lógica de negócio (ex.: pular check de role, inocular ID de usuário)?
- [ ] IDs sensíveis não são enumeráveis sem autenticação?

### Logs e auditoria

- [ ] Falhas de autenticação são logadas (sem expor senhas)?
- [ ] Eventos sensíveis (login, logout, mudança de permissão) são auditados?
- [ ] Nenhum dado sensível escrito em logs?

## Template de relatório

```
## Resultado da revisão: <app.py|<arquivo>>
- Crítica: N/A ou (descrição + linhas)
- Alta: N/A ou (descrição + linhas)
- Média: N/A ou (descrição + linhas)
- Baixa: N/A ou (descrição + linhas)

### Mitre Attack mapping
- T1552.001 — Credentials In Files — (como explorado)
- T1110.001 — Password Guessing — (como explorado)

### Reconhecimento
- [ ] Corrigido no código
- [ ] Alternativa documentada
- [ ] Bug report aberto para owner
```

## Pitfalls

- Não confie no trecho "está usando ?" — verifique o `execute` seguinte, não apenas o formato.
- Não olhe só o código do login — o banco pode ter outras tabelas com a mesma vulnerabilidade.
- Não decida o estilo — use a checklist; se houver gap, marque como "pendente".
- Não esqueça o rate limiting — muitas aplicações tem SQLi protegido, mas sem lockout de login.
- Não teste em produção — use ambiente isolado ou `mock` de banco.

## Como testar (exemplo)

```python
import app, sqlite3, os

conn = sqlite3.connect("teste.db")
conn.execute("CREATE TABLE usuarios (usuario TEXT, senha TEXT)")
conn.commit(); conn.close()

app.registrar_usuario("alice", "SenhorSeguro")
print("valido:", app.fazer_login("alice", "SenhorSeguro"))
print("errado:", app.fazer_login("alice", "senhaErrada"))

conn = sqlite3.connect("teste.db")
row = conn.execute(
    "SELECT senha FROM usuarios WHERE usuario='alice'"
).fetchone()
print("hash no db:", str(row[0]).startswith("pbkdf2_sha256"))
conn.close()
os.unlink("teste.db")
```

Saída esperada:

```
valido: True
errado: False
hash no db: True
```

## Verificação

- O hash no banco começa com `pbkdf2_sha256` (não é texto puro)
- Login com senha correta retorna True, com incorreta False
- Após 5 falhas consecutivas, o login é bloqueado por 15 minutos
- Nenhuma senha, token ou chave aparece em logs
- `.env` não está no controle de versão
- Consultas SQL usam placeholders, nunca f-string

## Referências

- OWASP Top 10 (2021): https://owasp.org/www-project-top-ten/
- MITRE ATT&CK: https://attack.mitre.org/
- Python `secrets` (tempo constante): https://docs.python.org/3/library/secrets.html
- Python `hashlib.pbkdf2_hmac`: https://docs.python.org/3/library/hashlib.html

This skill was generated from the security review of `d:/Cyber_Dio/dio-agent/agent/app.py`.
