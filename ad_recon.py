#!/usr/bin/env python3
"""
Active Directory Reconnaissance Script
Comprehensive AD enumeration and analysis tool for penetration testing and red teaming.

Supports:
- Guest mode (anonymous LDAP bind)
- Full mode (authenticated enumeration)
- User-inspect mode (single user analysis)

Author: AD Recon Tool
Version: 1.0
"""

import argparse
import json
import csv
import xml.etree.ElementTree as ET
import os
import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import socket
import re
from dataclasses import dataclass, asdict
from enum import Enum
import html
import base64

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, LEVEL, NTLM, SIMPLE
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
except ImportError:
    print("❌ Error: ldap3 library not found. Install with: pip install ldap3")
    sys.exit(1)

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"

@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    description: str
    details: Dict[str, Any]
    timestamp: str

class ADRecon:
    def __init__(self, dc_ip: str, domain: str, username: str = None, password: str = None, hash: str = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.hash = hash
        self.connection = None
        self.findings = []
        self.output_folder = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('errors.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def print_colored(self, message: str, color: str = Colors.WHITE, severity: Severity = None):
        """Print colored output with severity indicators"""
        if severity == Severity.HIGH:
            prefix = f"{Colors.RED}🔴 [{severity.value}]{Colors.END} "
        elif severity == Severity.MEDIUM:
            prefix = f"{Colors.YELLOW}🟠 [{severity.value}]{Colors.END} "
        elif severity == Severity.INFO:
            prefix = f"{Colors.GREEN}🟢 [{severity.value}]{Colors.END} "
        else:
            prefix = ""
        
        print(f"{prefix}{color}{message}{Colors.END}")

    def add_finding(self, severity: Severity, category: str, title: str, description: str, details: Dict[str, Any] = None):
        """Add a finding to the collection"""
        finding = Finding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            details=details or {},
            timestamp=datetime.now().isoformat()
        )
        self.findings.append(finding)
        self.print_colored(f"{title}: {description}", 
                          Colors.RED if severity == Severity.HIGH else Colors.YELLOW if severity == Severity.MEDIUM else Colors.GREEN,
                          severity)

    def connect_ldap(self, mode: str) -> bool:
        """Establish LDAP connection based on mode"""
        try:
            server = Server(self.dc_ip, get_info=ALL)
            
            if mode == "guest":
                self.print_colored("🔍 Attempting anonymous LDAP bind...", Colors.CYAN)
                self.connection = Connection(server, auto_bind=True)
            else:
                if not self.username:
                    self.print_colored("❌ Username required for authenticated modes", Colors.RED, Severity.HIGH)
                    return False
                
                if self.hash:
                    self.print_colored("🔐 Using NTLM hash authentication...", Colors.CYAN)
                    self.connection = Connection(server, user=f"{self.domain}\\{self.username}", 
                                               password=self.hash, authentication=NTLM, auto_bind=True)
                else:
                    if not self.password:
                        self.print_colored("❌ Password or hash required for authenticated modes", Colors.RED, Severity.HIGH)
                        return False
                    
                    self.print_colored("🔐 Using password authentication...", Colors.CYAN)
                    self.connection = Connection(server, user=f"{self.domain}\\{self.username}", 
                                               password=self.password, authentication=SIMPLE, auto_bind=True)
            
            if self.connection.bound:
                self.print_colored("✅ LDAP connection established successfully", Colors.GREEN)
                return True
            else:
                self.print_colored("❌ LDAP bind failed", Colors.RED, Severity.HIGH)
                return False
                
        except LDAPBindError as e:
            self.print_colored(f"❌ LDAP bind error: {e}", Colors.RED, Severity.HIGH)
            return False
        except LDAPSocketOpenError as e:
            self.print_colored(f"❌ Cannot connect to DC: {e}", Colors.RED, Severity.HIGH)
            return False
        except Exception as e:
            self.print_colored(f"❌ Connection error: {e}", Colors.RED, Severity.HIGH)
            return False

    def search_ldap(self, base_dn: str, search_filter: str, attributes: List[str] = None) -> List[Dict]:
        """Perform LDAP search and return results"""
        if not self.connection:
            return []
        
        try:
            if not attributes:
                attributes = ['*']
            
            self.connection.search(base_dn, search_filter, attributes=attributes, search_scope=SUBTREE)
            results = []
            
            for entry in self.connection.entries:
                entry_dict = {}
                for attr in entry.entry_attributes:
                    value = entry[attr].value
                    if isinstance(value, list) and len(value) == 1:
                        value = value[0]
                    entry_dict[attr] = value
                results.append(entry_dict)
            
            return results
        except Exception as e:
            self.logger.error(f"LDAP search error: {e}")
            return []

    def get_domain_admins(self) -> List[Dict]:
        """Enumerate Domain Admins group members"""
        self.print_colored("👑 Enumerating Domain Admins...", Colors.MAGENTA)
        
        # Get Domain Admins group
        domain_admins = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            "(&(objectClass=group)(sAMAccountName=Domain Admins))",
            ['member', 'memberOf']
        )
        
        if not domain_admins:
            return []
        
        admin_members = []
        processed_users = set()
        
        def resolve_group_members(group_dn: str):
            """Recursively resolve group members"""
            members = self.search_ldap(
                group_dn,
                "(objectClass=user)",
                ['sAMAccountName', 'displayName', 'userPrincipalName', 'adminCount', 'description']
            )
            
            for member in members:
                if member.get('sAMAccountName') and member['sAMAccountName'] not in processed_users:
                    processed_users.add(member['sAMAccountName'])
                    admin_members.append(member)
                    self.print_colored(f"[+] DOMAIN ADMIN: {member['sAMAccountName']}", Colors.RED, Severity.HIGH)
        
        # Process direct members
        if domain_admins[0].get('member'):
            for member_dn in domain_admins[0]['member']:
                resolve_group_members(member_dn)
        
        return admin_members

    def get_all_users(self) -> List[Dict]:
        """Enumerate all domain users"""
        self.print_colored("👥 Enumerating all domain users...", Colors.MAGENTA)
        
        users = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            "(&(objectClass=user)(objectCategory=person))",
            [
                'sAMAccountName', 'displayName', 'userPrincipalName', 'description',
                'userAccountControl', 'lastLogon', 'pwdLastSet', 'memberOf',
                'adminCount', 'servicePrincipalName', 'mail', 'title', 'department'
            ]
        )
        
        risky_users = []
        for user in users:
            uac = user.get('userAccountControl', 0)
            
            # Check for risky attributes
            if user.get('adminCount') == 1:
                self.add_finding(Severity.HIGH, "User Security", 
                               f"User with adminCount=1: {user.get('sAMAccountName')}",
                               "User has adminCount attribute set to 1")
                risky_users.append(user)
            
            if uac & 0x800000:  # DONT_REQ_PREAUTH
                self.add_finding(Severity.HIGH, "AS-REP Roasting", 
                               f"AS-REP roastable user: {user.get('sAMAccountName')}",
                               "User has DONT_REQ_PREAUTH flag set")
                self.print_colored(f"[!] AS-REP roastable: {user.get('sAMAccountName')}", Colors.YELLOW, Severity.HIGH)
            
            if uac & 0x20:  # PASSWD_NOTREQD
                self.add_finding(Severity.HIGH, "Password Security", 
                               f"Password not required: {user.get('sAMAccountName')}",
                               "User has PASSWD_NOTREQD flag set")
            
            if uac & 0x10000:  # pwdNeverExpires
                self.add_finding(Severity.MEDIUM, "Password Security", 
                               f"Password never expires: {user.get('sAMAccountName')}",
                               "User has pwdNeverExpires flag set")
        
        return users

    def analyze_descriptions(self, users: List[Dict]) -> List[str]:
        """Analyze user descriptions for potential credentials"""
        self.print_colored("🔎 Analyzing user descriptions for credentials...", Colors.MAGENTA)
        
        credential_candidates = []
        
        for user in users:
            description = user.get('description', '')
            if not description:
                continue
            
            # Rule 1: ≥6 chars, contains ≥3 types: upper/lower/digit/special
            if len(description) >= 6:
                has_upper = any(c.isupper() for c in description)
                has_lower = any(c.islower() for c in description)
                has_digit = any(c.isdigit() for c in description)
                has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in description)
                
                type_count = sum([has_upper, has_lower, has_digit, has_special])
                
                if type_count >= 3:
                    credential_candidates.append(f"{user.get('sAMAccountName')}: {description}")
                    self.add_finding(Severity.HIGH, "Credential Exposure", 
                                   f"Potential credential in description: {user.get('sAMAccountName')}",
                                   f"Description matches credential pattern: {description}")
                    self.print_colored(f"[!] Password pattern: {description} in user description", Colors.YELLOW, Severity.HIGH)
            
            # Rule 2: ≥6 chars, must include special characters + 1 more type
            if len(description) >= 6 and has_special:
                other_types = sum([has_upper, has_lower, has_digit])
                if other_types >= 1:
                    credential_candidates.append(f"{user.get('sAMAccountName')}: {description}")
        
        return credential_candidates

    def get_kerberoast_candidates(self, users: List[Dict]) -> List[Dict]:
        """Find users with SPNs for Kerberoasting"""
        self.print_colored("🍗 Finding Kerberoasting candidates...", Colors.MAGENTA)
        
        candidates = []
        for user in users:
            spn = user.get('servicePrincipalName')
            if spn:
                candidates.append(user)
                self.print_colored(f"[!] Kerberoast candidate: {user.get('sAMAccountName')} - {spn}", Colors.YELLOW, Severity.MEDIUM)
        
        return candidates

    def get_asrep_candidates(self, users: List[Dict]) -> List[Dict]:
        """Find users vulnerable to AS-REP roasting"""
        self.print_colored("🔐 Finding AS-REP roastable users...", Colors.MAGENTA)
        
        candidates = []
        for user in users:
            uac = user.get('userAccountControl', 0)
            if uac & 0x800000:  # DONT_REQ_PREAUTH
                candidates.append(user)
        
        return candidates

    def get_gpos(self) -> List[Dict]:
        """Enumerate Group Policy Objects"""
        self.print_colored("🏢 Enumerating Group Policy Objects...", Colors.MAGENTA)
        
        gpos = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            "(objectClass=groupPolicyContainer)",
            ['displayName', 'description', 'whenCreated', 'whenChanged', 'gPCFileSysPath']
        )
        
        # Check for suspicious GPO names
        suspicious_keywords = ['credential', 'password', 'admin', 'service', 'svc', 'test']
        for gpo in gpos:
            name = gpo.get('displayName', '').lower()
            for keyword in suspicious_keywords:
                if keyword in name:
                    self.add_finding(Severity.MEDIUM, "GPO Analysis", 
                                   f"Suspicious GPO name: {gpo.get('displayName')}",
                                   f"GPO name contains suspicious keyword: {keyword}")
        
        return gpos

    def get_computers(self) -> List[Dict]:
        """Enumerate computer objects with IP resolution"""
        self.print_colored("🖥️ Enumerating computers...", Colors.MAGENTA)
        
        computers = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            "(objectClass=computer)",
            ['name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 
             'lastLogonTimestamp', 'userAccountControl', 'managedBy', 'description']
        )
        
        computers_with_ips = []
        for computer in computers:
            hostname = computer.get('dNSHostName') or computer.get('name')
            if hostname:
                try:
                    ip = socket.gethostbyname(hostname)
                    computer['ip_address'] = ip
                    computers_with_ips.append(computer)
                except socket.gaierror:
                    computer['ip_address'] = "Unresolved"
                    computers_with_ips.append(computer)
        
        return computers_with_ips

    def get_printers(self) -> List[Dict]:
        """Enumerate printer objects"""
        self.print_colored("🖨️ Enumerating printers...", Colors.MAGENTA)
        
        printers = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            "(objectClass=printQueue)",
            ['name', 'serverName', 'location', 'description', 'comment', 'driverName']
        )
        
        printers_with_ips = []
        for printer in printers:
            server = printer.get('serverName')
            if server:
                try:
                    ip = socket.gethostbyname(server)
                    printer['ip_address'] = ip
                    printers_with_ips.append(printer)
                except socket.gaierror:
                    printer['ip_address'] = "Unresolved"
                    printers_with_ips.append(printer)
        
        return printers_with_ips

    def detect_misconfigurations(self, users: List[Dict], computers: List[Dict]):
        """Detect various misconfigurations"""
        self.print_colored("🛑 Detecting misconfigurations...", Colors.MAGENTA)
        
        # Check for stale accounts (>90 days)
        cutoff_date = datetime.now() - timedelta(days=90)
        
        for user in users:
            last_logon = user.get('lastLogon')
            if last_logon:
                try:
                    if isinstance(last_logon, str):
                        last_logon = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                    if last_logon < cutoff_date:
                        self.add_finding(Severity.MEDIUM, "Account Management", 
                                       f"Stale user account: {user.get('sAMAccountName')}",
                                       f"Last logon: {last_logon}")
                except:
                    pass
        
        # Check for machine accounts with adminCount=1
        for computer in computers:
            if computer.get('adminCount') == 1:
                self.add_finding(Severity.HIGH, "Computer Security", 
                               f"Machine account with adminCount=1: {computer.get('name')}",
                               "Machine account has adminCount attribute set to 1")

    def create_output_folder(self) -> str:
        """Create output folder with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_folder = f"./output/{timestamp}/"
        Path(output_folder).mkdir(parents=True, exist_ok=True)
        self.output_folder = output_folder
        return output_folder

    def save_json(self, data: Any, filename: str):
        """Save data as JSON"""
        filepath = os.path.join(self.output_folder, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    def save_csv(self, data: List[Dict], filename: str):
        """Save data as CSV"""
        if not data:
            return
        
        filepath = os.path.join(self.output_folder, filename)
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            if data:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)

    def save_txt(self, data: List[str], filename: str):
        """Save data as text file"""
        filepath = os.path.join(self.output_folder, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(f"{item}\n")

    def generate_html_report(self, data: Dict[str, Any]):
        """Generate comprehensive HTML report"""
        # Calculate statistics
        total_users = len(data.get('users', []))
        total_computers = len(data.get('computers', []))
        total_printers = len(data.get('printers', []))
        total_gpos = len(data.get('gpos', []))
        total_domain_admins = len(data.get('domain_admins', []))
        total_kerberoast = len(data.get('kerberoast_candidates', []))
        total_asrep = len(data.get('asrep_candidates', []))
        total_credential_candidates = len(data.get('credential_candidates', []))
        
        high_findings = len([f for f in self.findings if f.severity == Severity.HIGH])
        medium_findings = len([f for f in self.findings if f.severity == Severity.MEDIUM])
        info_findings = len([f for f in self.findings if f.severity == Severity.INFO])
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🧾 AD Recon Report - {self.domain}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .executive-summary {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 40px;
            border-left: 5px solid #007bff;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .summary-item {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .summary-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }}
        
        .summary-label {{
            color: #6c757d;
            font-weight: 500;
        }}
        
        .findings-section {{
            margin: 40px 0;
        }}
        
        .finding {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 5px solid;
            transition: transform 0.2s ease;
        }}
        
        .finding:hover {{
            transform: translateY(-2px);
        }}
        
        .finding.high {{
            border-left-color: #dc3545;
            background: linear-gradient(135deg, #fff5f5 0%, #ffe6e6 100%);
        }}
        
        .finding.medium {{
            border-left-color: #fd7e14;
            background: linear-gradient(135deg, #fff8f0 0%, #ffe8d1 100%);
        }}
        
        .finding.info {{
            border-left-color: #28a745;
            background: linear-gradient(135deg, #f0fff4 0%, #e6ffe6 100%);
        }}
        
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        
        .finding-description {{
            color: #6c757d;
            margin-bottom: 10px;
        }}
        
        .finding-meta {{
            font-size: 0.9em;
            color: #adb5bd;
        }}
        
        .data-section {{
            margin: 40px 0;
        }}
        
        .section-header {{
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
            color: white;
            padding: 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 0;
            cursor: pointer;
            user-select: none;
            transition: background 0.3s ease;
            position: relative;
        }}
        
        .section-header:hover {{
            background: linear-gradient(135deg, #5a6268 0%, #343a40 100%);
        }}
        
        .section-header::after {{
            content: '▼';
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            transition: transform 0.3s ease;
            font-size: 1.2em;
        }}
        
        .section-header.collapsed::after {{
            transform: translateY(-50%) rotate(-90deg);
        }}
        
        .section-content {{
            transition: max-height 0.3s ease, opacity 0.3s ease;
            overflow: hidden;
        }}
        
        .section-content.collapsed {{
            max-height: 0;
            opacity: 0;
        }}
        
        .search-container {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 0 0 10px 10px;
            border: 1px solid #dee2e6;
            border-top: none;
        }}
        
        .search-box {{
            width: 100%;
            padding: 15px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #007bff;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 0 0 10px 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        
        tr:hover {{
            background-color: #e9ecef;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-high {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-medium {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-info {{
            background: #28a745;
            color: white;
        }}
        
        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .content {{
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧾 AD Recon Report</h1>
            <div class="subtitle">
                <strong>Domain:</strong> {self.domain} | 
                <strong>DC:</strong> {self.dc_ip} | 
                <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="content">
            <div class="executive-summary">
                <h2 style="color: #2c3e50; margin-bottom: 20px;">📊 Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number">{high_findings}</div>
                        <div class="summary-label">High Risk Findings</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{medium_findings}</div>
                        <div class="summary-label">Medium Risk Findings</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{info_findings}</div>
                        <div class="summary-label">Info Findings</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{total_users}</div>
                        <div class="summary-label">Total Users</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{total_computers}</div>
                        <div class="summary-label">Computers</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{total_domain_admins}</div>
                        <div class="summary-label">Domain Admins</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{total_kerberoast}</div>
                        <div class="summary-label">Kerberoast Candidates</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{total_asrep}</div>
                        <div class="summary-label">AS-REP Candidates</div>
                    </div>
                </div>
            </div>
            
            <div class="findings-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🚨 High Risk Findings ({high_findings})</h2>
                    <div class="section-content">
                        {self._generate_findings_html(Severity.HIGH)}
                    </div>
                </div>
                
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">⚠️ Medium Risk Findings ({medium_findings})</h2>
                    <div class="section-content">
                        {self._generate_findings_html(Severity.MEDIUM)}
                    </div>
                </div>
                
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">ℹ️ Information Findings ({info_findings})</h2>
                    <div class="section-content">
                        {self._generate_findings_html(Severity.INFO)}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">👑 Domain Admins ({total_domain_admins})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('domain_admins', []), ['sAMAccountName', 'displayName', 'userPrincipalName', 'mail'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">👥 All Users ({total_users})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="userSearch" placeholder="🔍 Search users by name, email, or description...">
                        </div>
                        {self._generate_table_html(data.get('users', []), ['sAMAccountName', 'displayName', 'userPrincipalName', 'mail', 'description', 'lastLogon'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🍗 Kerberoasting Candidates ({total_kerberoast})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('kerberoast_candidates', []), ['sAMAccountName', 'displayName', 'servicePrincipalName', 'userPrincipalName'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔐 AS-REP Roastable Users ({total_asrep})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('asrep_candidates', []), ['sAMAccountName', 'displayName', 'userPrincipalName', 'mail'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🖥️ Computers ({total_computers})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('computers', []), ['name', 'ip_address', 'operatingSystem', 'lastLogon', 'description'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🖨️ Printers ({total_printers})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('printers', []), ['name', 'ip_address', 'location', 'description'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🏢 Group Policy Objects ({total_gpos})</h2>
                    <div class="section-content">
                        {self._generate_table_html(data.get('gpos', []), ['displayName', 'description', 'gPCFileSysPath', 'whenCreated'])}
                    </div>
                </div>
            </div>
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔑 Credential Candidates ({total_credential_candidates})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="credentialSearch" placeholder="🔍 Search credential candidates...">
                        </div>
                        {self._generate_credential_table_html(data.get('credential_candidates', []))}
                    </div>
                </div>
            </div>
            ''' if total_credential_candidates > 0 else ''}
        </div>
        
        <script>
            // Toggle section functionality
            function toggleSection(header) {{
                const section = header.parentElement;
                const content = section.querySelector('.section-content');
                const isCollapsed = content.classList.contains('collapsed');
                
                if (isCollapsed) {{
                    content.classList.remove('collapsed');
                    header.classList.remove('collapsed');
                }} else {{
                    content.classList.add('collapsed');
                    header.classList.add('collapsed');
                }}
            }}
            
            // Enhanced search functionality
            function setupSearch(searchBoxId, tableSelector) {{
                const searchBox = document.getElementById(searchBoxId);
                if (!searchBox) return;
                
                searchBox.addEventListener('keyup', function() {{
                    const input = this.value.toLowerCase();
                    const table = document.querySelector(tableSelector);
                    if (!table) return;
                    
                    const rows = table.getElementsByTagName('tr');
                    
                    for (let i = 1; i < rows.length; i++) {{
                        const row = rows[i];
                        const cells = row.getElementsByTagName('td');
                        let found = false;
                        
                        for (let j = 0; j < cells.length; j++) {{
                            if (cells[j].textContent.toLowerCase().indexOf(input) > -1) {{
                                found = true;
                                break;
                            }}
                        }}
                        
                        row.style.display = found ? '' : 'none';
                    }}
                }});
            }}
            
            // Setup searches
            setupSearch('userSearch', 'table');
            setupSearch('credentialSearch', 'table');
            
            // Add hover effects to findings
            document.querySelectorAll('.finding').forEach(finding => {{
                finding.addEventListener('mouseenter', function() {{
                    this.style.transform = 'translateY(-3px)';
                }});
                
                finding.addEventListener('mouseleave', function() {{
                    this.style.transform = 'translateY(0)';
                }});
            }});
        </script>
    </div>
</body>
</html>
        """
        
        filepath = os.path.join(self.output_folder, 'report.html')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _generate_findings_html(self, severity: Severity) -> str:
        """Generate HTML for findings of specific severity"""
        findings = [f for f in self.findings if f.severity == severity]
        if not findings:
            return '<div class="no-data">No findings of this severity level.</div>'
        
        html_parts = []
        for finding in findings:
            severity_class = severity.value.lower()
            severity_badge = f'<span class="severity-badge severity-{severity_class}">{severity.value}</span>'
            html_parts.append(f"""
                <div class="finding {severity_class}">
                    <div class="finding-title">
                        {severity_badge} {html.escape(finding.title)}
                    </div>
                    <div class="finding-description">
                        {html.escape(finding.description)}
                    </div>
                    <div class="finding-meta">
                        📁 Category: {finding.category} | ⏰ Time: {finding.timestamp}
                    </div>
                </div>
            """)
        
        return ''.join(html_parts)

    def _generate_table_html(self, data: List[Dict], columns: List[str]) -> str:
        """Generate HTML table from data"""
        if not data:
            return '<div class="no-data">No data available.</div>'
        
        html_parts = ['<table>', '<thead><tr>']
        for col in columns:
            html_parts.append(f'<th>{col}</th>')
        html_parts.append('</tr></thead><tbody>')
        
        for item in data:
            html_parts.append('<tr>')
            for col in columns:
                value = item.get(col, '')
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                elif value is None:
                    value = ''
                html_parts.append(f'<td>{html.escape(str(value))}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return ''.join(html_parts)

    def _generate_credential_table_html(self, credential_candidates: List[str]) -> str:
        """Generate HTML table for credential candidates"""
        if not credential_candidates:
            return '<div class="no-data">No credential candidates found.</div>'
        
        html_parts = ['<table>', '<thead><tr>', '<th>User</th>', '<th>Description</th>', '<th>Potential Credentials</th>', '</tr></thead><tbody>']
        
        for candidate in credential_candidates:
            # Parse the candidate string (format: "username: description")
            if ':' in candidate:
                parts = candidate.split(':', 1)
                username = parts[0].strip()
                description = parts[1].strip() if len(parts) > 1 else ''
            else:
                username = candidate.strip()
                description = ''
            
            # Extract potential credentials from description
            potential_creds = []
            if description:
                # Look for common credential patterns
                import re
                patterns = [
                    r'password[:\s]*([^\s]+)',  # password: value
                    r'pass[:\s]*([^\s]+)',      # pass: value
                    r'pwd[:\s]*([^\s]+)',       # pwd: value
                    r'([a-zA-Z0-9]{8,})',       # 8+ alphanumeric chars
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, description, re.IGNORECASE)
                    potential_creds.extend(matches)
            
            potential_creds_str = ', '.join(set(potential_creds)) if potential_creds else 'None detected'
            
            html_parts.append(f'<tr>')
            html_parts.append(f'<td>{html.escape(username)}</td>')
            html_parts.append(f'<td>{html.escape(description)}</td>')
            html_parts.append(f'<td>{html.escape(potential_creds_str)}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return ''.join(html_parts)

    def run_guest_mode(self):
        """Run reconnaissance in guest mode"""
        self.print_colored("🔍 Starting guest mode reconnaissance...", Colors.BLUE)
        
        if not self.connect_ldap("guest"):
            return False
        
        # Limited enumeration for guest mode
        users = self.get_all_users()
        computers = self.get_computers()
        printers = self.get_printers()
        
        # Save results
        output_folder = self.create_output_folder()
        self.save_json(users, 'all_users.json')
        self.save_csv(computers, 'computers_with_ips.csv')
        self.save_csv(printers, 'printers.csv')
        
        # Generate findings
        findings_data = {
            'users': users,
            'computers': computers,
            'printers': printers,
            'findings': [asdict(f) for f in self.findings]
        }
        
        self.save_json(findings_data, 'findings.json')
        self.generate_html_report(findings_data)
        
        self.print_colored(f"✅ Guest mode completed. Results saved to: {output_folder}", Colors.GREEN)
        return True

    def run_full_mode(self):
        """Run comprehensive reconnaissance in full mode"""
        self.print_colored("🔍 Starting full mode reconnaissance...", Colors.BLUE)
        
        if not self.connect_ldap("full"):
            return False
        
        # Comprehensive enumeration
        domain_admins = self.get_domain_admins()
        users = self.get_all_users()
        credential_candidates = self.analyze_descriptions(users)
        kerberoast_candidates = self.get_kerberoast_candidates(users)
        asrep_candidates = self.get_asrep_candidates(users)
        gpos = self.get_gpos()
        computers = self.get_computers()
        printers = self.get_printers()
        
        # Detect misconfigurations
        self.detect_misconfigurations(users, computers)
        
        # Save results
        output_folder = self.create_output_folder()
        
        # Save domain admins
        admin_names = [admin.get('sAMAccountName') for admin in domain_admins]
        self.save_txt(admin_names, 'domain_admins.txt')
        
        # Save credential candidates
        self.save_txt(credential_candidates, 'password_candidates.txt')
        
        # Save kerberoast candidates
        kerberoast_names = [candidate.get('sAMAccountName') for candidate in kerberoast_candidates]
        self.save_txt(kerberoast_names, 'kerberoast_candidates.txt')
        
        # Save AS-REP candidates
        asrep_names = [candidate.get('sAMAccountName') for candidate in asrep_candidates]
        self.save_txt(asrep_names, 'asrep_candidates.txt')
        
        # Save comprehensive data
        self.save_json(users, 'all_users.json')
        self.save_csv(computers, 'computers_with_ips.csv')
        self.save_csv(printers, 'printers.csv')
        
        # Generate findings
        findings_data = {
            'domain_admins': domain_admins,
            'users': users,
            'credential_candidates': credential_candidates,
            'kerberoast_candidates': kerberoast_candidates,
            'asrep_candidates': asrep_candidates,
            'gpos': gpos,
            'computers': computers,
            'printers': printers,
            'findings': [asdict(f) for f in self.findings]
        }
        
        self.save_json(findings_data, 'findings.json')
        self.generate_html_report(findings_data)
        
        self.print_colored(f"✅ Full mode completed. Results saved to: {output_folder}", Colors.GREEN)
        return True

    def run_user_inspect_mode(self, target_user: str):
        """Run single user inspection mode"""
        self.print_colored(f"🔍 Starting user inspection for: {target_user}", Colors.BLUE)
        
        if not self.connect_ldap("user-inspect"):
            return False
        
        # Search for specific user
        user_filter = f"(&(objectClass=user)(sAMAccountName={target_user}))"
        users = self.search_ldap(
            f"DC={self.domain.replace('.', ',DC=')}",
            user_filter,
            ['*']
        )
        
        if not users:
            self.print_colored(f"❌ User {target_user} not found", Colors.RED, Severity.HIGH)
            return False
        
        user = users[0]
        
        # Analyze user details
        credential_candidates = self.analyze_descriptions([user])
        kerberoast_candidates = self.get_kerberoast_candidates([user])
        asrep_candidates = self.get_asrep_candidates([user])
        
        # Save results
        output_folder = self.create_output_folder()
        
        user_report = {
            'user': user,
            'credential_candidates': credential_candidates,
            'kerberoast_candidates': kerberoast_candidates,
            'asrep_candidates': asrep_candidates,
            'findings': [asdict(f) for f in self.findings]
        }
        
        self.save_json(user_report, 'target_user_report.json')
        self.generate_html_report(user_report)
        
        self.print_colored(f"✅ User inspection completed. Results saved to: {output_folder}", Colors.GREEN)
        return True

def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ad_recon.py --mode guest --dc-ip 192.168.1.10 --domain corp.local
  python ad_recon.py --mode full --dc-ip 192.168.1.10 --domain corp.local --username admin --password Password123
  python ad_recon.py --mode user-inspect --dc-ip 192.168.1.10 --domain corp.local --username admin --password Password123 --target-user john.doe
        """
    )
    
    parser.add_argument('--mode', required=True, choices=['guest', 'full', 'user-inspect'],
                       help='Reconnaissance mode')
    parser.add_argument('--dc-ip', required=True, help='Domain Controller IP or hostname')
    parser.add_argument('--domain', required=True, help='FQDN of the domain (e.g., corp.local)')
    parser.add_argument('--username', help='Username (required for full and user-inspect modes)')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--hash', help='NTLM hash (alternative to password)')
    parser.add_argument('--target-user', help='Target user for user-inspect mode')
    parser.add_argument('--output-format', nargs='+', choices=['json', 'csv', 'xml'], default=['json'],
                       help='Output formats (default: json)')
    parser.add_argument('--output-folder', help='Output folder path')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode in ['full', 'user-inspect'] and not args.username:
        print("❌ Error: Username required for full and user-inspect modes")
        sys.exit(1)
    
    if args.mode == 'user-inspect' and not args.target_user:
        print("❌ Error: Target user required for user-inspect mode")
        sys.exit(1)
    
    if args.mode in ['full', 'user-inspect'] and not args.password and not args.hash:
        print("❌ Error: Password or hash required for full and user-inspect modes")
        sys.exit(1)
    
    # Create AD recon instance
    recon = ADRecon(
        dc_ip=args.dc_ip,
        domain=args.domain,
        username=args.username,
        password=args.password,
        hash=args.hash
    )
    
    # Run based on mode
    success = False
    if args.mode == 'guest':
        success = recon.run_guest_mode()
    elif args.mode == 'full':
        success = recon.run_full_mode()
    elif args.mode == 'user-inspect':
        success = recon.run_user_inspect_mode(args.target_user)
    
    if success:
        print(f"\n🎉 Reconnaissance completed successfully!")
        print(f"📁 Results saved to: {recon.output_folder}")
        print(f"📊 HTML report: {recon.output_folder}report.html")
    else:
        print("\n❌ Reconnaissance failed. Check errors.log for details.")
        sys.exit(1)

if __name__ == "__main__":
    main() 