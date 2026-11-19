# Configuracao de acesso ao APIC Cisco ACI
# Nao altere este arquivo - use variaveis de ambiente ou edite os valores abaixo

# APIC Controllers (SPB-VIV)
APIC_HOSTS = [
    "x.x.x.x",   # APIC01
    "x.x.x.x",   # APIC02
    "x.x.x.x",   # APIC03
]

# Credenciais (use variaveis de ambiente ou edite aqui)
APIC_USERNAME = "x.x.x.x"  # ou use: os.environ.get("APIC_USER")
APIC_PASSWORD = "x.x.x.x"       # ou use: os.environ.get("APIC_PASS")

# Tenant padrao para validacao
DEFAULT_TENANT = "Common"  # Ajuste para o tenant do seu ambiente

# Timeout para queries API (em segundos)
API_TIMEOUT = 30

# Ignorar verificacao SSL (recomendado para labs)
VERIFY_SSL = False
