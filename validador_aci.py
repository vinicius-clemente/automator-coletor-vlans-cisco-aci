#!/usr/bin/env python3
"""
Validador de Configuracao Cisco ACI (APIC REST API)
---------------------------------------------------
Modo somente leitura - apenas consulta o estado atual do fabric.
Nao altera nenhuma configuracao.

Uso:
    python validador_aci.py --vlans input/vlans.csv
    python validador_aci.py --epgs input/epgs.csv
    python validador_aci.py --domains input/domains.csv
    python validador_aci.py --static-ports input/static_ports.csv
    python validador_aci.py --all  # valida tudo
"""

import os
import sys
import csv
import json
import argparse
import getpass
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("ERRO: instale as dependencias: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("AVISO: rich nao instalado, usando saida basica")

# Importar configuracao local
try:
    from apic_config import (
        APIC_HOSTS, APIC_USERNAME, APIC_PASSWORD,
        DEFAULT_TENANT, API_TIMEOUT, VERIFY_SSL
    )
except ImportError:
    print("ERRO: arquivo apic_config.py nao encontrado")
    sys.exit(1)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class VlanInfo:
    vlan_id: str
    name: str = ""
    bd_exists: bool = False
    bd_name: str = ""
    bd_vrf: str = ""
    epg_exists: bool = False
    epg_name: str = ""
    epg_app: str = ""
    epg_tenant: str = ""
    domain_exists: bool = False
    domain_name: str = ""
    domain_attached: bool = False
    static_port_exists: bool = False
    static_ports_found: List[str] = field(default_factory=list)
    static_ports_missing: List[str] = field(default_factory=list)
    status: str = "PENDENTE"
    observations: str = ""


@dataclass
class EpgInfo:
    epg_name: str
    app_profile: str
    tenant: str
    exists: bool = False
    bd_name: str = ""
    bd_linked: bool = False
    domain_attached: bool = False
    domain_name: str = ""
    static_ports_count: int = 0
    status: str = "PENDENTE"
    observations: str = ""


@dataclass
class DomainInfo:
    domain_name: str
    tenant: str
    exists: bool = False
    epgs_attached: List[str] = field(default_factory=list)
    status: str = "PENDENTE"
    observations: str = ""


@dataclass
class StaticPortInfo:
    epg_name: str
    app_profile: str
    tenant: str
    node: str
    port: str
    vlan: str
    exists: bool = False
    encap_correct: bool = False
    status: str = "PENDENTE"
    observations: str = ""


# =============================================================================
# APIC CLIENT
# =============================================================================

class APICClient:
    """Cliente REST API do APIC (somente leitura)."""

    def __init__(self, hosts: List[str], username: str, password: str,
                 timeout: int = 30, verify_ssl: bool = False):
        self.hosts = hosts
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.base_url = ""
        self.authenticated = False

    def authenticate(self) -> bool:
        """Autentica no APIC. Tenta cada host ate conseguir."""
        for host in self.hosts:
            try:
                url = f"https://{host}/api/aaaLogin.json"
                payload = {
                    "aaaUser": {
                        "attributes": {
                            "name": self.username,
                            "pwd": self.password
                        }
                    }
                }
                resp = self.session.post(
                    url, json=payload,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if "error" not in data:
                        self.base_url = f"https://{host}"
                        self.authenticated = True
                        return True
            except Exception as e:
                continue
        return False

    def query(self, endpoint: str, filters: Optional[Dict] = None) -> Optional[List[Dict]]:
        """Executa query GET na API (somente leitura). Reautentica se a sessao expirou."""
        if not self.authenticated:
            return None

        url = f"{self.base_url}{endpoint}"

        def _do_request():
            resp = self.session.get(
                url, params=filters,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            data = {}
            try:
                data = resp.json()
            except Exception:
                pass
            return resp.status_code, data

        def _session_expired(status_code, data):
            if status_code in (401, 403):
                return True
            if status_code == 200 or status_code == 400:
                for obj in data.get("imdata", []):
                    err = obj.get("error", {}).get("attributes", {})
                    code = err.get("code", "")
                    if code in ("401", "403"):
                        return True
            return False

        try:
            status_code, data = _do_request()
            if status_code == 200 and "imdata" in data:
                return data["imdata"]

            # Sessao expirada ou invalida: reautentica e tenta mais uma vez
            if _session_expired(status_code, data) and self.authenticate():
                status_code, data = _do_request()
                if status_code == 200 and "imdata" in data:
                    return data["imdata"]
        except Exception:
            pass
        return None

    def get_class(self, class_name: str, filter_str: Optional[str] = None) -> List[Dict]:
        """Consulta classe ACI."""
        endpoint = f"/api/class/{class_name}.json"
        params = {}
        if filter_str:
            params["query-target-filter"] = filter_str
        result = self.query(endpoint, params)
        return result if result else []

    def get_children(self, parent_dn: str, subclass: str = None) -> List[Dict]:
        """Consulta filhos de um MO."""
        endpoint = f"/api/mo/{parent_dn}.json"
        params = {"query-target": "children"}
        result = self.query(endpoint, params)
        if not result:
            return []
        if subclass:
            return [r for r in result if subclass in r]
        return result

    def get_mo(self, dn: str) -> Optional[Dict]:
        """Consulta Managed Object por DN."""
        endpoint = f"/api/mo/{dn}.json"
        result = self.query(endpoint)
        if result and len(result) > 0:
            return result[0]
        return None


# =============================================================================
# CSV READERS
# =============================================================================

def read_vlans_csv(filepath: str) -> List[Dict[str, str]]:
    """Le CSV de VLANs (apenas vlan_id). Aceita delimitador ',' ou ';'."""
    vlans = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        first_line = f.readline().strip()
        delim = ';' if ';' in first_line else ','
        f.seek(0)
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            vid = row.get('vlan_id', '').strip()
            if vid:
                vlans.append({'vlan_id': vid})
    return vlans


def read_epgs_csv(filepath: str) -> List[Dict[str, str]]:
    """Le CSV de EPGs."""
    epgs = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            epgs.append({
                'epg_name': row.get('epg_name', '').strip(),
                'app_profile': row.get('app_profile', '').strip(),
                'tenant': row.get('tenant', '').strip()
            })
    return epgs


def read_domains_csv(filepath: str) -> List[Dict[str, str]]:
    """Le CSV de Domains."""
    domains = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains.append({
                'domain_name': row.get('domain_name', '').strip(),
                'tenant': row.get('tenant', '').strip()
            })
    return domains


def read_static_ports_csv(filepath: str) -> List[Dict[str, str]]:
    """Le CSV de Static Ports."""
    ports = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ports.append({
                'epg_name': row.get('epg_name', '').strip(),
                'app_profile': row.get('app_profile', '').strip(),
                'tenant': row.get('tenant', '').strip(),
                'node': row.get('node', '').strip(),
                'port': row.get('port', '').strip(),
                'vlan': row.get('vlan', '').strip()
            })
    return ports


# =============================================================================
# VALIDATORS
# =============================================================================

class ACIValidator:
    """Validador de configuracao ACI (somente leitura)."""

    def __init__(self, client: APICClient):
        self.client = client

    def validate_vlan(self, vlan_id: str, tenant: str = "") -> VlanInfo:
        """Valida uma VLAN: procura EPG VLAN{id}-EPG, BD VLAN{id}-BD, Domain e Static Ports."""
        info = VlanInfo(vlan_id=vlan_id)

        epg_name = f"VLAN{vlan_id}-EPG"
        bd_name = f"VLAN{vlan_id}-BD"

        # 1. Verificar EPG por nome (busca global, extrai tenant do DN)
        epg_filter = f'eq(fvAEPg.name,"{epg_name}")'
        epgs = self.client.get_class("fvAEPg", epg_filter)
        if epgs:
            for epg in epgs:
                epg_attrs = epg.get("fvAEPg", {}).get("attributes", {})
                dn = epg_attrs.get("dn", "")
                info.epg_exists = True
                info.epg_name = epg_name
                for p in dn.split("/"):
                    if p.startswith("tn-"):
                        info.epg_tenant = p[3:]
                    if p.startswith("ap-"):
                        info.epg_app = p[3:]
                break

        # 2. Se EPG existe, verificar BD, dominio e static ports via get_children
        if info.epg_tenant and info.epg_app:
            epg_dn = f"uni/tn-{info.epg_tenant}/ap-{info.epg_app}/epg-{epg_name}"

            # Verificar BD vinculado ao EPG
            rsbds = self.client.get_children(epg_dn, "fvRsBd")
            if rsbds:
                bd_tdn = rsbds[0].get("fvRsBd", {}).get("attributes", {}).get("tDn", "")
                if bd_name in bd_tdn:
                    info.bd_exists = True
                    info.bd_name = bd_name
                    if "/ctx-" in bd_tdn:
                        info.bd_vrf = bd_tdn.split("/ctx-")[-1].split("/")[0]

            # Verificar dominios anexados
            doms = self.client.get_children(epg_dn, "fvRsDomAtt")
            if doms:
                info.domain_exists = True
                dom_tdn = doms[0].get("fvRsDomAtt", {}).get("attributes", {}).get("tDn", "")
                if "/phys-" in dom_tdn:
                    info.domain_name = dom_tdn.split("/phys-")[-1]

            # Verificar Static Ports
            static_ports = self.client.get_children(epg_dn, "fvRsPathAtt")
            if static_ports:
                info.static_port_exists = True
                for sp in static_ports:
                    attrs = sp.get("fvRsPathAtt", {}).get("attributes", {})
                    path = attrs.get("tDn", "")
                    encap = attrs.get("encap", "")
                    info.static_ports_found.append(f"{path} (encap={encap})")

        # 3. Fallback: verificar BD diretamente por DN (caso EPG nao exista)
        bd_tenant = info.epg_tenant or tenant
        if not info.bd_exists and bd_tenant:
            bd_dn = f"uni/tn-{bd_tenant}/BD-{bd_name}"
            bd_data = self.client.query(f"/api/mo/{bd_dn}.json")
            if bd_data:
                info.bd_exists = True
                info.bd_name = bd_name
                bd_attrs = bd_data[0].get("fvBD", {}).get("attributes", {})
                if "/ctx-" in bd_attrs.get("dn", ""):
                    info.bd_vrf = bd_attrs["dn"].split("/ctx-")[-1].split("/")[0]

        # Determinar status
        missing = []
        if not info.bd_exists:
            missing.append(f"BD({bd_name})")
        if not info.epg_exists:
            missing.append(f"EPG({epg_name})")
        if not info.static_port_exists:
            missing.append("STATIC_PORT")

        if missing:
            info.status = "INCOMPLETO"
            info.observations = f"Falta: {', '.join(missing)}"
        else:
            info.status = "OK"
            info.observations = f"BD OK, EPG OK, {len(info.static_ports_found)} static ports"

        return info

    def validate_epg(self, epg_name: str, app_profile: str, tenant: str) -> EpgInfo:
        """Valida um EPG."""
        info = EpgInfo(
            epg_name=epg_name,
            app_profile=app_profile,
            tenant=tenant
        )

        epg_dn = f"uni/tn-{tenant}/ap-{app_profile}/epg-{epg_name}"
        epg_filter = f'eq(fvAEPg.dn,"{epg_dn}")'
        epgs = self.client.get_class("fvAEPg", epg_filter)

        if epgs:
            info.exists = True

            # Verificar relacao com BD (filho do EPG)
            rsbds = self.client.get_children(epg_dn, "fvRsBd")
            if rsbds:
                info.bd_linked = True
                bd_tdn = rsbds[0].get("fvRsBd", {}).get("attributes", {}).get("tDn", "")
                if "/BD-" in bd_tdn:
                    info.bd_name = bd_tdn.split("/BD-")[-1]

            # Verificar dominios anexados (filho do EPG)
            doms = self.client.get_children(epg_dn, "fvRsDomAtt")
            if doms:
                info.domain_attached = True
                dom_tdn = doms[0].get("fvRsDomAtt", {}).get("attributes", {}).get("tDn", "")
                if "/phys-" in dom_tdn:
                    info.domain_name = dom_tdn.split("/phys-")[-1]

            # Contar static ports (filho do EPG)
            static_ports = self.client.get_children(epg_dn, "fvRsPathAtt")
            info.static_ports_count = len(static_ports)

        # Status
        missing = []
        if not info.exists:
            missing.append("EPG")
        if not info.bd_linked:
            missing.append("BD")
        if not info.domain_attached:
            missing.append("DOMAIN")

        if missing:
            info.status = "INCOMPLETO"
            info.observations = f"Falta: {', '.join(missing)}"
        else:
            info.status = "OK"
            info.observations = f"BD OK, Domain OK, {info.static_ports_count} static ports"

        return info

    def validate_domain(self, domain_name: str, tenant: str,
                        expected_epgs: Optional[List[str]] = None) -> DomainInfo:
        """Valida um Physical Domain e verifica se EPGs esperados estao anexados."""
        info = DomainInfo(
            domain_name=domain_name,
            tenant=tenant
        )

        dom_filter = f'eq(physDomP.name,"{domain_name}")'
        doms = self.client.get_class("physDomP", dom_filter)

        if doms:
            info.exists = True
            dom_dn = doms[0].get("physDomP", {}).get("attributes", {}).get("dn", "")

            epg_filter = f'eq(fvRsDomAtt.tDn,"{dom_dn}")'
            epg_atts = self.client.get_class("fvRsDomAtt", epg_filter)
            for att in epg_atts:
                tdn = att.get("fvRsDomAtt", {}).get("attributes", {}).get("dn", "")
                if "/epg-" in tdn:
                    epg_name = tdn.split("/epg-")[-1].split("/")[0]
                    info.epgs_attached.append(epg_name)

        if not info.exists:
            info.status = "NAO_ENCONTRADO"
            info.observations = "Domain nao existe no APIC"
        else:
            info.status = "OK"
            if expected_epgs:
                missing = [e for e in expected_epgs if e not in info.epgs_attached]
                if missing:
                    info.status = "INCOMPLETO"
                    info.observations = f"Domain OK, {len(info.epgs_attached)} EPGs, falta: {', '.join(missing)}"
                else:
                    info.observations = f"Domain OK, {len(info.epgs_attached)} EPGs, todos do CSV anexados"
            else:
                info.observations = f"Domain existe, {len(info.epgs_attached)} EPGs anexados"

        return info

    def validate_static_port(self, epg_name: str, app_profile: str,
                             tenant: str, node: str, port: str, vlan: str) -> StaticPortInfo:
        """Valida uma Static Port."""
        info = StaticPortInfo(
            epg_name=epg_name,
            app_profile=app_profile,
            tenant=tenant,
            node=node,
            port=port,
            vlan=vlan
        )

        epg_dn = f"uni/tn-{tenant}/ap-{app_profile}/epg-{epg_name}"

        # Construir path DN
        # VPC: node="201-202" -> protpaths-201-202/pathep-[VPC-NAME]
        # Individual: node="201" -> paths-201/pathep-[eth1/10]
        if "-" in node:
            path_dn = f"topology/pod-1/protpaths-{node}/pathep-[{port}]"
        else:
            path_dn = f"topology/pod-1/paths-{node}/pathep-[{port}]"
        sp_dn = f"{epg_dn}/rspathAtt-[{path_dn}]"

        # Verificar se static port existe
        sp_filter = f'eq(fvRsPathAtt.dn,"{sp_dn}")'
        sps = self.client.get_class("fvRsPathAtt", sp_filter)

        if sps:
            info.exists = True
            attrs = sps[0].get("fvRsPathAtt", {}).get("attributes", {})
            encap = attrs.get("encap", "")
            # Encap format: vlan-{vlan_id}
            if encap == f"vlan-{vlan}":
                info.encap_correct = True

        # Status
        if not info.exists:
            info.status = "NAO_ENCONTRADO"
            info.observations = "Static port nao existe"
        elif not info.encap_correct:
            info.status = "ENCAP_INCORRETO"
            info.observations = "Static port existe mas encap esta errado"
        else:
            info.status = "OK"
            info.observations = "Static port configurado corretamente"

        return info


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Gera relatorios de validacao."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_vlan_report(self, results: List[VlanInfo], filename: str = "vlan_validation.csv"):
        """Gera relatorio de validacao de VLANs."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'vlan_id', 'bd_exists', 'bd_vrf', 'epg_exists', 'epg_name',
                'domain_exists', 'static_port_exists', 'static_ports_found',
                'status', 'observations'
            ])
            for r in results:
                writer.writerow([
                    r.vlan_id,
                    r.bd_exists,
                    r.bd_vrf,
                    r.epg_exists,
                    r.epg_name,
                    r.domain_exists,
                    r.static_port_exists,
                    '; '.join(r.static_ports_found),
                    r.status,
                    r.observations
                ])
        return filepath

    def generate_epg_report(self, results: List[EpgInfo], filename: str = "epg_validation.csv"):
        """Gera relatorio de validacao de EPGs."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'epg_name', 'app_profile', 'tenant', 'exists', 'bd_name',
                'bd_linked', 'domain_attached', 'domain_name',
                'static_ports_count', 'status', 'observations'
            ])
            for r in results:
                writer.writerow([
                    r.epg_name,
                    r.app_profile,
                    r.tenant,
                    r.exists,
                    r.bd_name,
                    r.bd_linked,
                    r.domain_attached,
                    r.domain_name,
                    r.static_ports_count,
                    r.status,
                    r.observations
                ])
        return filepath

    def generate_domain_report(self, results: List[DomainInfo], filename: str = "domain_validation.csv"):
        """Gera relatorio de validacao de Domains."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'domain_name', 'tenant', 'exists', 'epgs_attached',
                'status', 'observations'
            ])
            for r in results:
                writer.writerow([
                    r.domain_name,
                    r.tenant,
                    r.exists,
                    '; '.join(r.epgs_attached),
                    r.status,
                    r.observations
                ])
        return filepath

    def generate_static_port_report(self, results: List[StaticPortInfo], filename: str = "static_port_validation.csv"):
        """Gera relatorio de validacao de Static Ports."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'epg_name', 'app_profile', 'tenant', 'node', 'port', 'vlan',
                'exists', 'encap_correct', 'status', 'observations'
            ])
            for r in results:
                writer.writerow([
                    r.epg_name,
                    r.app_profile,
                    r.tenant,
                    r.node,
                    r.port,
                    r.vlan,
                    r.exists,
                    r.encap_correct,
                    r.status,
                    r.observations
                ])
        return filepath

    def generate_summary(self, all_results: Dict[str, Any], filename: str = "summary.txt"):
        """Gera resumo da validacao."""
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("RELATORIO DE VALIDACAO CISCO ACI\n")
            f.write(f"Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            if 'vlans' in all_results:
                vlans = all_results['vlans']
                ok = sum(1 for v in vlans if v.status == "OK")
                incompleto = sum(1 for v in vlans if v.status == "INCOMPLETO")
                f.write(f"VLANS: {len(vlans)} total | {ok} OK | {incompleto} incompletos\n")
                f.write("-" * 40 + "\n")
                for v in vlans:
                    if v.status != "OK":
                        f.write(f"  VLAN {v.vlan_id}: {v.observations}\n")
                f.write("\n")

            if 'epgs' in all_results:
                epgs = all_results['epgs']
                ok = sum(1 for e in epgs if e.status == "OK")
                incompleto = sum(1 for e in epgs if e.status == "INCOMPLETO")
                f.write(f"EPGS: {len(epgs)} total | {ok} OK | {incompleto} incompletos\n")
                f.write("-" * 40 + "\n")
                for e in epgs:
                    if e.status != "OK":
                        f.write(f"  EPG {e.epg_name}: {e.observations}\n")
                f.write("\n")

            if 'domains' in all_results:
                domains = all_results['domains']
                ok = sum(1 for d in domains if d.status == "OK")
                nao_encontrado = sum(1 for d in domains if d.status == "NAO_ENCONTRADO")
                f.write(f"DOMAINS: {len(domains)} total | {ok} OK | {nao_encontrado} nao encontrados\n")
                f.write("-" * 40 + "\n")
                for d in domains:
                    if d.status != "OK":
                        f.write(f"  DOMAIN {d.domain_name}: {d.observations}\n")
                f.write("\n")

            if 'static_ports' in all_results:
                sps = all_results['static_ports']
                ok = sum(1 for s in sps if s.status == "OK")
                nao_encontrado = sum(1 for s in sps if s.status == "NAO_ENCONTRADO")
                f.write(f"STATIC PORTS: {len(sps)} total | {ok} OK | {nao_encontrado} nao encontrados\n")
                f.write("-" * 40 + "\n")
                for s in sps:
                    if s.status != "OK":
                        f.write(f"  {s.node}/{s.port} EPG:{s.epg_name}: {s.observations}\n")
                f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("FIM DO RELATORIO\n")
            f.write("=" * 80 + "\n")

        return filepath


# =============================================================================
# RICH UI
# =============================================================================

def print_banner():
    """Imprime banner do programa."""
    if HAS_RICH:
        console = Console()
        console.print(Panel.fit(
            "[bold cyan]Validador de Configuracao Cisco ACI[/bold cyan]\n"
            "[dim]Modo somente leitura - nao altera configuracao[/dim]",
            border_style="cyan"
        ))
    else:
        print("=" * 60)
        print("  Validador de Configuracao Cisco ACI")
        print("  Modo somente leitura - nao altera configuracao")
        print("=" * 60)


def print_summary_table(title: str, results: List[Any], key_fields: List[str]):
    """Imprime tabela resumo com Rich."""
    if not HAS_RICH:
        for r in results:
            print(f"  {r.status}: {getattr(r, key_fields[0], '')}")
        return

    console = Console()
    table = Table(title=title, box=box.ROUNDED, show_lines=True)

    # Adicionar colunas baseado nos campos
    for field_name in key_fields:
        table.add_column(field_name, style="cyan")

    table.add_column("Status", style="bold")
    table.add_column("Observacoes", style="dim")

    # Adicionar linhas
    for r in results:
        row = []
        for field_name in key_fields:
            val = getattr(r, field_name, "")
            if isinstance(val, bool):
                val = "SIM" if val else "NAO"
            elif isinstance(val, list):
                val = ", ".join(str(v) for v in val) if val else "-"
            row.append(str(val) if val else "-")

        # Cor do status
        status = r.status
        if status == "OK":
            status_style = "[bold green]OK[/bold green]"
        elif status == "INCOMPLETO":
            status_style = "[bold red]INCOMPLETO[/bold red]"
        elif status == "NAO_ENCONTRADO":
            status_style = "[bold yellow]NAO ENCONTRADO[/bold yellow]"
        else:
            status_style = f"[bold]{status}[/bold]"

        row.append(status_style)
        row.append(r.observations)
        table.add_row(*row)

    console.print(table)


# =============================================================================
# MAIN
# =============================================================================

def get_credentials() -> Tuple[str, str]:
    """Obtem credenciais do APIC."""
    username = APIC_USERNAME
    password = APIC_PASSWORD

    if not username:
        username = input("Usuario APIC: ")
    if not password:
        password = getpass.getpass("Senha APIC: ")

    return username, password


def main():
    """Funcao principal."""
    parser = argparse.ArgumentParser(
        description="Validador de Configuracao Cisco ACI (somente leitura)"
    )
    parser.add_argument("--vlans", help="CSV com lista de VLANs")
    parser.add_argument("--epgs", help="CSV com lista de EPGs")
    parser.add_argument("--domains", help="CSV com lista de Physical Domains")
    parser.add_argument("--static-ports", help="CSV com lista de Static Ports")
    parser.add_argument("--all", action="store_true", help="Valida todos os CSVs do diretorio input/")
    parser.add_argument("--tenant", help="Tenant para filtrar (default: Common)")
    parser.add_argument("--output", default="output", help="Diretorio de saida (default: output)")
    parser.add_argument("--apic", help="IP do APIC (override)")
    parser.add_argument("--user", help="Usuario APIC")
    parser.add_argument("--password", help="Senha APIC")
    parser.add_argument("--no-rich", action="store_true", help="Desabilita interface Rich")

    args = parser.parse_args()

    # Override config
    if args.apic:
        global APIC_HOSTS
        APIC_HOSTS = [args.apic]
    if args.user:
        global APIC_USERNAME
        APIC_USERNAME = args.user
    if args.password:
        global APIC_PASSWORD
        APIC_PASSWORD = args.password

    print_banner()

    # Credenciais
    username, password = get_credentials()
    if not password:
        print("ERRO: senha e obrigatoria")
        sys.exit(1)

    # Conectar ao APIC
    if HAS_RICH:
        console = Console()
        with console.status("[bold cyan]Conectando ao APIC..."):
            client = APICClient(
                hosts=APIC_HOSTS,
                username=username,
                password=password,
                timeout=API_TIMEOUT,
                verify_ssl=VERIFY_SSL
            )
            authenticated = client.authenticate()
    else:
        print("Conectando ao APIC...")
        client = APICClient(
            hosts=APIC_HOSTS,
            username=username,
            password=password,
            timeout=API_TIMEOUT,
            verify_ssl=VERIFY_SSL
        )
        authenticated = client.authenticate()

    if not authenticated:
        print("ERRO: nao foi possivel autenticar no APIC")
        print(f"Hosts tentados: {', '.join(APIC_HOSTS)}")
        sys.exit(1)

    if HAS_RICH:
        console.print(f"[green]Autenticado com sucesso em {client.base_url}[/green]")
    else:
        print(f"Autenticado em {client.base_url}")

    # Validator
    validator = ACIValidator(client)
    report = ReportGenerator(args.output)
    all_results = {}

    # Validar VLANs
    if args.vlans or args.all:
        filepath = args.vlans or "input/vlans.csv"
        if os.path.exists(filepath):
            if HAS_RICH:
                console.print(f"\n[bold]Validando VLANs de {filepath}...[/bold]")
            else:
                print(f"\nValidando VLANs de {filepath}...")

            vlans_data = read_vlans_csv(filepath)
            tenant = args.tenant or DEFAULT_TENANT

            if HAS_RICH:
                console.print(f"  Padrao: EPG=VLAN{{id}}-EPG, BD=VLAN{{id}}-BD")
            print(f"  Lidas {len(vlans_data)} VLANs do CSV")

            results = []
            for v in vlans_data:
                if HAS_RICH:
                    with console.status(f"  Validando VLAN {v['vlan_id']}..."):
                        result = validator.validate_vlan(v['vlan_id'], tenant)
                else:
                    print(f"  Validando VLAN {v['vlan_id']}...")
                    result = validator.validate_vlan(v['vlan_id'], tenant)
                results.append(result)

            all_results['vlans'] = results
            print_summary_table(
                "Resultado - VLANs",
                results,
                ['vlan_id', 'bd_exists', 'bd_vrf', 'epg_exists', 'domain_exists', 'static_port_exists']
            )
            report.generate_vlan_report(results)
        else:
            print(f"AVISO: arquivo {filepath} nao encontrado")

    # Validar EPGs
    if args.epgs or args.all:
        filepath = args.epgs or "input/epgs.csv"
        if os.path.exists(filepath):
            if HAS_RICH:
                console.print(f"\n[bold]Validando EPGs de {filepath}...[/bold]")
            else:
                print(f"\nValidando EPGs de {filepath}...")

            epgs_data = read_epgs_csv(filepath)
            results = []
            for e in epgs_data:
                if HAS_RICH:
                    with console.status(f"  Validando EPG {e['epg_name']}..."):
                        result = validator.validate_epg(e['epg_name'], e['app_profile'], e['tenant'])
                else:
                    print(f"  Validando EPG {e['epg_name']}...")
                    result = validator.validate_epg(e['epg_name'], e['app_profile'], e['tenant'])
                results.append(result)

            all_results['epgs'] = results
            print_summary_table(
                "Resultado - EPGs",
                results,
                ['epg_name', 'app_profile', 'tenant', 'exists', 'bd_linked', 'domain_attached', 'static_ports_count']
            )
            report.generate_epg_report(results)
        else:
            print(f"AVISO: arquivo {filepath} nao encontrado")

    # Validar Domains
    if args.domains or args.all:
        filepath = args.domains or "input/domains.csv"
        if os.path.exists(filepath):
            if HAS_RICH:
                console.print(f"\n[bold]Validando Domains de {filepath}...[/bold]")
            else:
                print(f"\nValidando Domains de {filepath}...")

            domains_data = read_domains_csv(filepath)

            # Carregar EPGs esperados para verificacao cruzada
            expected_epgs = None
            epgs_filepath = args.epgs or "input/epgs.csv"
            if os.path.exists(epgs_filepath):
                epgs_data = read_epgs_csv(epgs_filepath)
                expected_epgs = [f"{e['epg_name']}" for e in epgs_data]
                print(f"  EPGs esperados do CSV: {', '.join(expected_epgs)}")

            results = []
            for d in domains_data:
                if HAS_RICH:
                    with console.status(f"  Validando Domain {d['domain_name']}..."):
                        result = validator.validate_domain(d['domain_name'], d['tenant'], expected_epgs)
                else:
                    print(f"  Validando Domain {d['domain_name']}...")
                    result = validator.validate_domain(d['domain_name'], d['tenant'], expected_epgs)
                results.append(result)

            all_results['domains'] = results
            print_summary_table(
                "Resultado - Domains",
                results,
                ['domain_name', 'tenant', 'exists', 'epgs_attached']
            )
            report.generate_domain_report(results)
        else:
            print(f"AVISO: arquivo {filepath} nao encontrado")

    # Validar Static Ports
    if args.static_ports or args.all:
        filepath = args.static_ports or "input/static_ports.csv"
        if os.path.exists(filepath):
            if HAS_RICH:
                console.print(f"\n[bold]Validando Static Ports de {filepath}...[/bold]")
            else:
                print(f"\nValidando Static Ports de {filepath}...")

            ports_data = read_static_ports_csv(filepath)
            results = []
            for p in ports_data:
                if HAS_RICH:
                    with console.status(f"  Validando {p['node']}/{p['port']}..."):
                        result = validator.validate_static_port(
                            p['epg_name'], p['app_profile'], p['tenant'],
                            p['node'], p['port'], p['vlan']
                        )
                else:
                    print(f"  Validando {p['node']}/{p['port']}...")
                    result = validator.validate_static_port(
                        p['epg_name'], p['app_profile'], p['tenant'],
                        p['node'], p['port'], p['vlan']
                    )
                results.append(result)

            all_results['static_ports'] = results
            print_summary_table(
                "Resultado - Static Ports",
                results,
                ['node', 'port', 'epg_name', 'vlan', 'exists', 'encap_correct']
            )
            report.generate_static_port_report(results)
        else:
            print(f"AVISO: arquivo {filepath} nao encontrado")

    # Gerar resumo final
    if all_results:
        summary_path = report.generate_summary(all_results)
        if HAS_RICH:
            console.print(f"\n[green]Relatorios gerados em {args.output}/[/green]")
            console.print(f"  - {summary_path}")
            console.print(f"  - {args.output}/vlan_validation.csv")
            console.print(f"  - {args.output}/epg_validation.csv")
            console.print(f"  - {args.output}/domain_validation.csv")
            console.print(f"  - {args.output}/static_port_validation.csv")
        else:
            print(f"\nRelatorios gerados em {args.output}/")
    else:
        print("\nNenhuma validacao solicitada. Use --vlans, --epgs, --domains, --static-ports ou --all")


if __name__ == "__main__":
    main()
