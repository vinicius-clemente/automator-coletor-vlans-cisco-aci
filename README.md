# Automator Coletor & Validador de VLANs - Cisco ACI

Ferramenta de automação desenvolvida em Python para auditoria e validação completa de VLANs em ambientes **Cisco ACI (Application Centric Infrastructure)**. O script conecta-se ao APIC / Fabric ACI e cruza os dados de entrada definidos em arquivos CSV (`input/`) contra o estado real da infraestrutura, validando **Physical Domains**, **VLAN Pools**, **EPGs (Endpoint Groups)** e **Static Ports** nos Leaf switches.

## Funcionalidades

- **Auditoria Baseada em Inventário CSV (`input/`):** Lê automaticamente arquivos estruturados contendo os domínios físicos, EPGs, VLAN IDs e mapeamentos de portas estáticas a serem verificados.
- **Validação Ponta a Ponta no Fabric ACI:**
  - **Domains (`domains.csv`):** Verifica a existência e associação de Physical/VMM Domains por Tenant.
  - **EPGs (`epgs.csv`):** Valida a presença dos Endpoint Groups dentro dos respectivos Application Profiles e Tenants.
  - **VLANs (`vlans.csv`):** Checa a alocação e encapsulamento dos VLAN IDs nos pools e EPGs do fabric.
  - **Static Ports (`static_ports.csv`):** Audita os bindings de interfaces físicas/lógicas (`node`, `port`, `vlan`) em cada EPG.
- **Saída Flexível (Tela, CSV e Log CLI):** Exibe o progresso e os resultados em tempo real no terminal, exporta relatórios consolidados em `.csv` na pasta `output/` e permite redirecionamento nativo via CLI (`tee`) para auditorias e evidências de mudança.

## Estrutura do Projeto

    automator-coletor-vlans-cisco-aci/
    ├── input/
    │   ├── domains.csv
    │   ├── epgs.csv
    │   ├── static_ports.csv
    │   └── vlans.csv
    ├── output/
    │   └── (relatórios CSV gerados automaticamente)
    ├── validador_aci.py
    ├── requirements.txt
    └── README.md

## Formato dos Arquivos de Entrada (`input/`)

- **`domains.csv`**: `domain_name,tenant`
- **`epgs.csv`**: `epg_name,app_profile,tenant`
- **`vlans.csv`**: `vlan_id`
- **`static_ports.csv`**: `epg_name,app_profile,tenant,node,port,vlan`

## Tecnologias Utilizadas

- **Python 3.x**
- **Requests / Cobra SDK / Paramiko:** Comunicação com a API REST do Cisco APIC e/ou consultas CLI (`moquery` / `show`) no fabric ACI.
- **CSV / Argparse:** Processamento estruturado de planilhas de entrada/saída e execução parametrizada via linha de comando.

## Como Utilizar

1. Clone o repositório:

       git clone https://github.com/vinicius-clemente/automator-coletor-vlans-cisco-aci.git
       cd automator-coletor-vlans-cisco-aci

2. Instale as dependências:

       pip install -r requirements.txt

3. Preencha os arquivos CSV dentro da pasta `input/` com os dados do seu ambiente Cisco ACI (Domains, EPGs, VLANs e Static Ports).

4. Execute a validação completa exibindo na tela e salvando o log de evidência em `.txt` (além da geração automática do relatório CSV em `output/`):

       python3 validador_aci.py --all 2>&1 | tee resultado01.txt

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
