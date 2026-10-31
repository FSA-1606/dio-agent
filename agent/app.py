import sqlite3
import hashlib
import secrets
import logging
import time
import os
from threading import Lock

# ------------------------------------------------------------------ #
# 1) Auditoria: log de falhas de login sem expor senhas             #
# ------------------------------------------------------------------ #
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "login_attempts.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ------------------------------------------------------------------ #
# 2) Rate limiting (bloqueio por usuário). Em produção, troque por   #
#    Redis / memória distribuída para que o bloqueio valha em todo  #
#    o processo (não só em memória da thread).                      #
# ------------------------------------------------------------------ #
_attempts = {}
_attempts_lock = Lock()
MAX_FAILURES = 5            # tentativas antes do bloqueio
LOCKOUT_SECONDS = 900       # 15 minutos


def _chave_identificador(usuario):
    return "user:{}".format(usuario)


def _esta_bloqueado(identificador):
    with _attempts_lock:
        registro = _attempts.get(identificador)
        if not registro:
            return False
        tentativas, bloqueado_ate = registro
        if bloqueado_ate and time.time() < bloqueado_ate:
            return True
        # Se atingiu o limite, inicia o bloqueio vigente
        if tentativas >= MAX_FAILURES:
            _attempts[identificador] = (tentativas, time.time() + LOCKOUT_SECONDS)
            return True
        return False


def _registrar_falha(identificador):
    with _attempts_lock:
        tentativas, _ = _attempts.get(identificador, (0, 0))
        _attempts[identificador] = (tentativas + 1, 0)
        # NOTA: 'identificador' pode ser um nome de usuário; nunca logue a senha.
        logging.warning("Falha de login para %s (tentativa %d)", identificador, tentativas + 1)


def _zerar_contagem(identificador):
    with _attempts_lock:
        _attempts.pop(identificador, None)


# ------------------------------------------------------------------ #
# 3) Hash seguro de senha (stdlib: PBKDF2-HMAC-SHA256)              #
#    - sem dependências externas                                     #
#    - salt aleatório (secrets)                                      #
#    - 260.000 iterações (ajuste conforme cryptocurrendo)            #
# ------------------------------------------------------------------ #
def _gerar_salt():
    return secrets.token_bytes(16)


def _hashear_senha(senha):
    salt = _gerar_salt()
    iteracoes = 260000
    digest = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, iteracoes)
    # Formato: pbkdf2_sha256$iteracoes$salt_hex$hash_hex
    return "pbkdf2_sha256${}${}${}".format(iteracoes, salt.hex(), digest.hex())


def _verificar_senha(senha, hash_armazenado):
    try:
        algoritmo, iteracoes, salt_hex, hash_hex = hash_armazenado.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        # Usa secrets.compare_digest para comparação em tempo constante
        digest = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, int(iteracoes))
        return secrets.compare_digest(digest.hex(), hash_hex)
    except (ValueError, AttributeError):
        # Formato de hash inválido (ex.: senha antiga salva em texto puro)
        return False


# ------------------------------------------------------------------ #
# 4) Acesso ao banco (apenas leitura, row_factory para dict-like)     #
# ------------------------------------------------------------------ #
def _obter_conexao():
    # O caminho é relativo ao diretório do próprio módulo, não ao CWD,
    # para evitar que a localidade da execução:altere o banco acessado.
    dir_modulo = os.path.dirname(os.path.abspath(__file__))
    conexao = sqlite3.connect(os.path.join(dir_modulo, "banco_de_dados.db"))
    conexao.row_factory = sqlite3.Row
    return conexao


# ------------------------------------------------------------------ #
# 5) API de registro (seed) sem expor detalhes                        #
# ------------------------------------------------------------------ #
def registrar_usuario(usuario, senha):
    """Cria um usuário com senha hasheada. Usar na seed/inicialização."""
    if _esta_bloqueado(_chave_identificador(usuario)):
        return False  # Usuário temporariamente bloqueado

    conexao = _obter_conexao()
    try:
        cursor = conexao.cursor()
        cursor.execute("SELECT 1 FROM usuarios WHERE usuario=?", (usuario,))
        if cursor.fetchone():
            return False  # Usuário já existe
        cursor.execute(
            "INSERT INTO usuarios (usuario, senha) VALUES (?, ?)",
            (usuario, _hashear_senha(senha)),
        )
        conexao.commit()
        return True
    finally:
        conexao.close()


# ------------------------------------------------------------------ #
# 6) Login corrigido                                                #
# ------------------------------------------------------------------ #
def fazer_login(usuario, senha):
    """Faz login com verificação segura de senha.

    Corrigências:
      - Senha só é comparada em memória (nunca no SQL).
      - Sem SQL injection: consulta só pelo usuário, com placeholders.
      - Rate limiting por usuário.
      - Log de falhas sem expor a senha.
      - Comparação em tempo constante (secrets.compare_digest).
    """
    if not usuario or not senha:
        _registrar_falha("anon:{}".format(usuario or "vazio"))
        return False

    if _esta_bloqueado(_chave_identificador(usuario)):
        _registrar_falha(_chave_identificador(usuario))
        return False

    conexao = _obter_conexao()
    try:
        cursor = conexao.cursor()
        # Busca APENAS pelo usuário; a senha é verificada em memória abaixo.
        cursor.execute("SELECT senha FROM usuarios WHERE usuario=?", (usuario,))
        resultado = cursor.fetchone()
    finally:
        conexao.close()

    if resultado is None or not _verificar_senha(senha, resultado["senha"]):
        _registrar_falha(_chave_identificador(usuario))
        return False

    _zerar_contagem(_chave_identificador(usuario))
    return True

