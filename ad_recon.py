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
import subprocess

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
        
        # Normalize domain name - if short domain provided, try to discover full domain
        if '.' not in self.domain:
            self.print_colored(f"🔍 Short domain detected: {self.domain}. Attempting to discover full domain...", Colors.CYAN)
            discovered_domain = self._discover_full_domain()
            if discovered_domain:
                self.domain = discovered_domain
                self.print_colored(f"✅ Discovered full domain: {self.domain}", Colors.GREEN)
            else:
                self.print_colored(f"⚠️ Could not discover full domain. Using: {self.domain}.local", Colors.YELLOW, Severity.MEDIUM)
                self.domain = f"{self.domain}.local"
        
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

    def _discover_full_domain(self) -> str:
        """Try to discover the full domain name using various methods"""
        try:
            # Method 1: Try nltest
            result = subprocess.run(['nltest', '/dsgetdc:' + self.domain], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Domain Name:' in line:
                        domain_name = line.split('Domain Name:')[1].strip()
                        if domain_name and '.' in domain_name:
                            return domain_name
            
            # Method 2: Try DNS query
            try:
                import socket
                # Try common domain suffixes
                for suffix in ['.local', '.corp', '.internal', '.lan', '.domain']:
                    test_domain = self.domain + suffix
                    try:
                        socket.gethostbyname(test_domain)
                        return test_domain
                    except socket.gaierror:
                        continue
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"Domain discovery failed: {e}")
        
        return None

    def _get_search_base_dn(self) -> str:
        """Get the correct search base DN for the domain"""
        if '.' in self.domain:
            return f"DC={self.domain.replace('.', ',DC=')}"
        else:
            return f"DC={self.domain},DC=local"

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
                    
                    # Try different authentication approaches
                    auth_success = False
                    
                    # Method 1: Standard domain\username format
                    try:
                        self.connection = Connection(server, user=f"{self.domain}\\{self.username}", 
                                                   password=self.password, authentication=SIMPLE, auto_bind=True)
                        if self.connection.bound:
                            auth_success = True
                    except Exception as e:
                        self.print_colored(f"⚠️ Method 1 failed: {e}", Colors.YELLOW, Severity.MEDIUM)
                    
                    # Method 2: Try short domain name
                    if not auth_success:
                        try:
                            short_domain = self.domain.split('.')[0]
                            self.connection = Connection(server, user=f"{short_domain}\\{self.username}", 
                                                       password=self.password, authentication=SIMPLE, auto_bind=True)
                            if self.connection.bound:
                                auth_success = True
                        except Exception as e:
                            self.print_colored(f"⚠️ Method 2 failed: {e}", Colors.YELLOW, Severity.MEDIUM)
                    
                    # Method 3: Try UPN format
                    if not auth_success:
                        try:
                            self.connection = Connection(server, user=f"{self.username}@{self.domain}", 
                                                       password=self.password, authentication=SIMPLE, auto_bind=True)
                            if self.connection.bound:
                                auth_success = True
                        except Exception as e:
                            self.print_colored(f"⚠️ Method 3 failed: {e}", Colors.YELLOW, Severity.MEDIUM)
                    
                    # Method 4: Try just username (if in same domain context)
                    if not auth_success:
                        try:
                            self.connection = Connection(server, user=self.username, 
                                                       password=self.password, authentication=SIMPLE, auto_bind=True)
                            if self.connection.bound:
                                auth_success = True
                        except Exception as e:
                            self.print_colored(f"⚠️ Method 4 failed: {e}", Colors.YELLOW, Severity.MEDIUM)
                    
                    # If all methods failed, set connection to None
                    if not auth_success:
                        self.connection = None
            
            if self.connection and self.connection.bound:
                self.print_colored("✅ LDAP connection established successfully", Colors.GREEN)
                return True
            else:
                self.print_colored("❌ LDAP bind failed - all authentication methods failed", Colors.RED, Severity.HIGH)
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
            
            # Set a very high limit to get all results (remove 1000 user limit)
            # Try with different size limits and controls
            try:
                self.connection.search(base_dn, search_filter, attributes=attributes, search_scope=SUBTREE, size_limit=0)
            except Exception as e:
                if "sizeLimitExceeded" in str(e) or "00002095" in str(e):
                    # Try with a larger limit
                    self.connection.search(base_dn, search_filter, attributes=attributes, search_scope=SUBTREE, size_limit=10000)
                else:
                    raise e
                    
            # If we still don't get enough results, try with paged results
            if len(self.connection.entries) < 1000:
                try:
                    # Try paged search
                    self.connection.search(base_dn, search_filter, attributes=attributes, search_scope=SUBTREE, size_limit=0, paged_size=1000)
                except Exception as e2:
                    self.logger.debug(f"Paged search also failed: {e2}")
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
            # Check if it's a permission error
            if "insufficientAccessRights" in str(e) or "00002098" in str(e):
                self.print_colored(f"⚠️ Permission denied for search: {search_filter}", Colors.YELLOW, Severity.MEDIUM)
            return []

    def get_domain_admins(self) -> List[Dict]:
        """Enumerate Domain Admins group members"""
        self.print_colored("👑 Enumerating Domain Admins...", Colors.MAGENTA)
        
        # Get Domain Admins group
        search_base = self._get_search_base_dn()
        self.print_colored(f"🔍 Using search base: {search_base}", Colors.CYAN)
        
        domain_admins = self.search_ldap(
            search_base,
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
                ['sAMAccountName', 'displayName', 'userPrincipalName', 'adminCount', 'description', 
                 'userAccountControl', 'lastLogon', 'pwdLastSet', 'mail']
            )
            
            for member in members:
                if member.get('sAMAccountName') and member['sAMAccountName'] not in processed_users:
                    processed_users.add(member['sAMAccountName'])
                    
                    # Process member with additional columns (same as get_all_users)
                    uac = member.get('userAccountControl', 0)
                    
                    # Add disabled/enabled status
                    is_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
                    member['isDisabled'] = 'Disabled' if is_disabled else 'Enabled'
                    
                    # Add password in description flag
                    description = member.get('description', '')
                    has_password_in_desc = self._has_password_pattern(description)
                    member['hasPasswordInDesc'] = 'Yes' if has_password_in_desc else 'No'
                    
                    # Add last logon days
                    last_logon = member.get('lastLogon')
                    last_logon_days = self._calculate_last_logon_days(last_logon)
                    member['lastLogonDays'] = last_logon_days
                    
                    # Add password age days
                    pwd_last_set = member.get('pwdLastSet')
                    password_age_days = self._calculate_password_age_days(pwd_last_set)
                    member['passwordAgeDays'] = password_age_days
                    
                    admin_members.append(member)
                    self.print_colored(f"[+] DOMAIN ADMIN: {member['sAMAccountName']}", Colors.RED, Severity.HIGH)
                    
                    # Check for password in description
                    description = member.get('description', '')
                    if description and self._has_password_pattern(description):
                        self.print_colored(f"🔴 [HIGH] Password found in Domain Admin description: {member['sAMAccountName']}: {description}", Colors.RED, Severity.HIGH)
                        self.add_finding(Severity.HIGH, "Credential Exposure", 
                                       f"Password in Domain Admin description: {member['sAMAccountName']}",
                                       f"Description contains password pattern: {description}")
        
        # Process direct members
        if domain_admins[0].get('member'):
            for member_dn in domain_admins[0]['member']:
                resolve_group_members(member_dn)
        
        return admin_members

    def get_all_users(self) -> List[Dict]:
        """Enumerate all domain users"""
        self.print_colored("👥 Enumerating all domain users...", Colors.MAGENTA)
        
        search_base = self._get_search_base_dn()
        users = self.search_ldap(
            search_base,
            "(&(objectClass=user)(objectCategory=person))",
            [
                'sAMAccountName', 'displayName', 'userPrincipalName', 'description',
                'userAccountControl', 'lastLogon', 'pwdLastSet', 'memberOf',
                'adminCount', 'servicePrincipalName', 'mail', 'title', 'department'
            ]
        )
        
        # Process users and add additional columns
        processed_users = []
        
        # Group findings by type
        admin_count_users = []
        asrep_users = []
        password_not_required_users = []
        password_never_expires_users = []
        
        for user in users:
            uac = user.get('userAccountControl', 0)
            
            # Add disabled/enabled status
            is_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
            user['isDisabled'] = 'Disabled' if is_disabled else 'Enabled'
            
            # Add password in description flag
            description = user.get('description', '')
            has_password_in_desc = self._has_password_pattern(description)
            user['hasPasswordInDesc'] = 'Yes' if has_password_in_desc else 'No'
            
            # Add last logon days
            last_logon = user.get('lastLogon')
            last_logon_days = self._calculate_last_logon_days(last_logon)
            user['lastLogonDays'] = last_logon_days
            
            # Add password age days
            pwd_last_set = user.get('pwdLastSet')
            password_age_days = self._calculate_password_age_days(pwd_last_set)
            user['passwordAgeDays'] = password_age_days
            
            # Collect risky attributes for grouping
            if user.get('adminCount') == 1:
                admin_count_users.append(user.get('sAMAccountName'))
            
            if uac & 0x800000:  # DONT_REQ_PREAUTH
                asrep_users.append(user.get('sAMAccountName'))
                self.print_colored(f"[!] AS-REP roastable: {user.get('sAMAccountName')}", Colors.YELLOW, Severity.HIGH)
            
            if uac & 0x20:  # PASSWD_NOTREQD
                password_not_required_users.append(user.get('sAMAccountName'))
            
            if uac & 0x10000:  # pwdNeverExpires
                password_never_expires_users.append(user.get('sAMAccountName'))
            
            processed_users.append(user)
        
        # Add grouped findings with detailed risk descriptions
        if admin_count_users:
            self.add_finding(Severity.HIGH, "User Security", 
                           "Users with adminCount=1",
                           f"Multiple users have adminCount attribute set to 1:\n" + "\n".join([f"• {user}" for user in admin_count_users]) +
                           "\n\n**Why this is risky:** The adminCount=1 attribute indicates these accounts are protected by the AdminSDHolder process, meaning they have elevated privileges and are considered administrative accounts. This creates a larger attack surface for privilege escalation." +
                           "\n\n**How attackers can exploit this:** Attackers can target these accounts for privilege escalation attacks, password spraying, or lateral movement. Compromising any of these accounts provides elevated access to the domain.")
        
        if asrep_users:
            self.add_finding(Severity.HIGH, "AS-REP Roasting", 
                           "AS-REP roastable users",
                           f"Multiple users have DONT_REQ_PREAUTH flag set:\n" + "\n".join([f"• {user}" for user in asrep_users]) +
                           "\n\n**Why this is risky:** Users with DONT_REQ_PREAUTH flag are vulnerable to AS-REP roasting attacks. This flag disables Kerberos pre-authentication, allowing attackers to request authentication tickets without knowing the password." +
                           "\n\n**How attackers can exploit this:** Attackers can use tools like Rubeus or Impacket to perform AS-REP roasting attacks, potentially cracking weak passwords offline without triggering account lockouts.")
        
        if password_not_required_users:
            self.add_finding(Severity.HIGH, "Password Security", 
                           "Users with password not required",
                           f"Multiple users have PASSWD_NOTREQD flag set:\n" + "\n".join([f"• {user}" for user in password_not_required_users]) +
                           "\n\n**Why this is risky:** Accounts with PASSWD_NOTREQD flag can authenticate without a password, making them extremely vulnerable to unauthorized access. This is a critical security misconfiguration." +
                           "\n\n**How attackers can exploit this:** Attackers can authenticate to these accounts without any password, gaining immediate access to the domain. This can be used for initial access, privilege escalation, or lateral movement.")
        
        if password_never_expires_users:
            self.add_finding(Severity.MEDIUM, "Password Security", 
                           "Users with password never expires",
                           f"Multiple users have pwdNeverExpires flag set:\n" + "\n".join([f"• {user}" for user in password_never_expires_users]) +
                           "\n\n**Why this is risky:** Passwords that never expire increase the risk of credential compromise over time. Users may use weak passwords indefinitely, and compromised credentials remain valid permanently." +
                           "\n\n**How attackers can exploit this:** Attackers can use compromised credentials indefinitely, and the lack of password rotation makes it easier to maintain persistent access to the domain.")
        
        return processed_users

    def analyze_descriptions(self, users: List[Dict]) -> List[str]:
        """Analyze user descriptions for potential credentials"""
        self.print_colored("🔎 Analyzing user descriptions for credentials...", Colors.MAGENTA)
        
        credential_candidates = []
        seen_entries = set()  # Track unique entries to prevent duplicates
        password_findings = []  # Group password findings together
        
        for user in users:
            description = user.get('description', '')
            if not description:
                continue
            
            # Skip false positives - filter out built-in accounts and computer/domain patterns
            description_lower = description.lower()
            if any(pattern in description_lower for pattern in ['built-in account', 'computer/domain']):
                continue
            
            # Check if description meets credential criteria
            if len(description) >= 6:
                has_upper = any(c.isupper() for c in description)
                has_lower = any(c.islower() for c in description)
                has_digit = any(c.isdigit() for c in description)
                has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in description)
                
                type_count = sum([has_upper, has_lower, has_digit, has_special])
                
                # Rule 1: ≥6 chars, contains ≥3 types: upper/lower/digit/special
                # Rule 2: ≥6 chars, must include special characters + 1 more type
                if type_count >= 3 or (has_special and sum([has_upper, has_lower, has_digit]) >= 1):
                    entry = f"{user.get('sAMAccountName')}: {description}"
                    if entry not in seen_entries:
                        credential_candidates.append(entry)
                        seen_entries.add(entry)
                        password_findings.append(f"User {user.get('sAMAccountName')}: {description}")
                        self.print_colored(f"[!] Password pattern: {description} in user description", Colors.YELLOW, Severity.HIGH)
        
        # Add grouped finding for all password discoveries
        if password_findings:
            self.add_finding(Severity.HIGH, "Credential Exposure", 
                           "Potential credentials found in user descriptions",
                           "Multiple users have potential passwords in their descriptions:\n" + "\n".join(password_findings) +
                           "\n\n**Why this is risky:** Storing passwords in user descriptions is a critical security vulnerability. These passwords are stored in plain text and can be easily retrieved by anyone with read access to Active Directory." +
                           "\n\n**How attackers can exploit this:** Attackers can extract these passwords directly from LDAP queries without any cracking or brute force attempts. This provides immediate access to user accounts and can be used for privilege escalation, lateral movement, or data exfiltration.")
        
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
        
        search_base = self._get_search_base_dn()
        gpos = self.search_ldap(
            search_base,
            "(objectClass=groupPolicyContainer)",
            ['displayName', 'description', 'whenCreated', 'whenChanged', 'gPCFileSysPath']
        )
        
        # Check for suspicious GPO names
        suspicious_keywords = ['credential', 'password', 'admin', 'service', 'svc', 'test']
        suspicious_gpos = []
        
        for gpo in gpos:
            name = gpo.get('displayName', '').lower()
            for keyword in suspicious_keywords:
                if keyword in name:
                    suspicious_gpos.append(f"{gpo.get('displayName')} (contains '{keyword}')")
                    break  # Only add once per GPO
        
        # Add grouped finding for suspicious GPOs
        if suspicious_gpos:
            self.add_finding(Severity.MEDIUM, "GPO Analysis", 
                           "Suspicious GPO names detected",
                           f"Multiple GPOs contain suspicious keywords:\n" + "\n".join([f"• {gpo}" for gpo in suspicious_gpos]) +
                           "\n\n**Why this is risky:** GPOs with suspicious names may contain misconfigurations, hardcoded credentials, or security bypasses. Attackers often target GPOs for privilege escalation and persistence." +
                           "\n\n**How attackers can exploit this:** Attackers can analyze these GPOs for embedded credentials, security misconfigurations, or use them for privilege escalation through GPO abuse techniques like SYSVOL exploitation.")
        
        return gpos

    def get_interesting_groups(self) -> List[Dict]:
        """Enumerate groups with interesting names (admin, super, etc.)"""
        self.print_colored("🔍 Enumerating interesting groups...", Colors.MAGENTA)
        
        search_base = self._get_search_base_dn()
        all_groups = self.search_ldap(
            search_base,
            "(objectClass=group)",
            ['sAMAccountName', 'displayName', 'description', 'member', 'memberOf', 'adminCount']
        )
        
        if not all_groups:
            return []
        
        # Define interesting keywords for group names
        interesting_keywords = [
            'admin', 'administrator', 'super', 'power', 'privilege', 'elevated',
            'security', 'audit', 'backup', 'service', 'support', 'helpdesk',
            'it', 'network', 'system', 'domain', 'enterprise', 'global',
            'local', 'builtin', 'management', 'executive', 'finance', 'hr',
            'sales', 'marketing', 'development', 'test', 'qa', 'devops'
        ]
        
        interesting_groups = []
        for group in all_groups:
            group_name = group.get('sAMAccountName', '')
            display_name = group.get('displayName', '')
            
            # Check if group name contains interesting keywords
            is_interesting = any(keyword in group_name.lower() for keyword in interesting_keywords) if group_name else False
            is_interesting_display = any(keyword in display_name.lower() for keyword in interesting_keywords) if display_name else False
            
            if is_interesting or is_interesting_display:
                interesting_groups.append(group)
                self.print_colored(f"🔍 Found interesting group: {group.get('sAMAccountName')}", Colors.CYAN)
        
        return interesting_groups

    def resolve_group_members(self, groups: List[Dict], existing_users: List[Dict]) -> tuple[List[Dict], List[str]]:
        """Resolve all group members and find missing users. Returns (successful_users, failed_lookups)"""
        self.print_colored("🔍 Resolving group members and finding missing users...", Colors.MAGENTA)
        
        all_group_members = []
        failed_lookups = []
        existing_usernames = {user.get('sAMAccountName') for user in existing_users}
        processed_members = set()  # Track to avoid duplicates
        
        for group in groups:
            group_name = group.get('sAMAccountName', 'Unknown')
            
            # Get group members
            members = group.get('member', [])
            if not members:
                continue
            
            for member_dn in members:
                # Extract username from DN
                try:
                    # Handle different DN formats
                    if member_dn.startswith('CN='):
                        username = member_dn.split(',')[0].replace('CN=', '')
                    elif member_dn.startswith('S-1-5-'):
                        # Skip SID entries
                        continue
                    else:
                        # Try to extract username from other formats
                        username = member_dn.split(',')[0]
                        if '=' in username:
                            username = username.split('=')[1]
                    
                    # Skip if username is too short or contains invalid characters
                    if len(username) < 2 or username in ['', ' ', 'Domain Admins', 'Enterprise Admins']:
                        continue
                    
                    if username not in processed_members:
                        processed_members.add(username)
                        
                        # Check if this user is missing from our LDAP results
                        if username not in existing_usernames:
                            # Try to get user details from LDAP by displayName first, then by sAMAccountName
                            user_details = self.search_ldap(
                                self._get_search_base_dn(),
                                f"(&(objectClass=user)(displayName={username}))",
                                ['sAMAccountName', 'displayName', 'description', 'userAccountControl', 
                                 'lastLogon', 'pwdLastSet', 'mail', 'title', 'department']
                            )
                            
                            # If not found by displayName, try by sAMAccountName
                            if not user_details:
                                user_details = self.search_ldap(
                                    self._get_search_base_dn(),
                                    f"(&(objectClass=user)(sAMAccountName={username}))",
                                    ['sAMAccountName', 'displayName', 'description', 'userAccountControl', 
                                     'lastLogon', 'pwdLastSet', 'mail', 'title', 'department']
                                )
                            
                            if user_details:
                                user = user_details[0]
                                # Process user with additional columns
                                uac = user.get('userAccountControl', 0)
                                
                                # Add disabled/enabled status
                                is_disabled = bool(uac & 0x2)  # ACCOUNTDISABLE flag
                                user['isDisabled'] = 'Disabled' if is_disabled else 'Enabled'
                                
                                # Add password in description flag
                                description = user.get('description', '')
                                has_password_in_desc = self._has_password_pattern(description)
                                user['hasPasswordInDesc'] = 'Yes' if has_password_in_desc else 'No'
                                
                                # Add last logon days
                                last_logon = user.get('lastLogon')
                                last_logon_days = self._calculate_last_logon_days(last_logon)
                                user['lastLogonDays'] = last_logon_days
                                
                                # Add password age days
                                pwd_last_set = user.get('pwdLastSet')
                                password_age_days = self._calculate_password_age_days(pwd_last_set)
                                user['passwordAgeDays'] = password_age_days
                                
                                # Add group membership info
                                user['found_in_group'] = group_name
                                
                                all_group_members.append(user)
                                
                                # Check for password in description and report immediately
                                if has_password_in_desc:
                                    self.print_colored(f"🔴 [HIGH] Password found in missing user description: {username}: {description}", Colors.RED, Severity.HIGH)
                                    self.add_finding(Severity.HIGH, "Credential Exposure", 
                                                   f"Password in missing user description: {username}",
                                                   f"Description contains password pattern: {description}")
                            else:
                                # Add to failed lookups
                                failed_lookups.append(f"{username} (group: {group_name})")
                except Exception as e:
                    self.logger.debug(f"Error processing member {member_dn}: {e}")
                    continue
        
        self.print_colored(f"✅ Found {len(all_group_members)} additional users from group enumeration", Colors.GREEN)
        self.print_colored(f"⚠️ {len(failed_lookups)} user lookups failed", Colors.YELLOW, Severity.MEDIUM)
        return all_group_members, failed_lookups

    def get_all_groups(self) -> List[Dict]:
        """Enumerate all groups in the domain"""
        self.print_colored("👥 Enumerating all groups...", Colors.MAGENTA)
        
        search_base = self._get_search_base_dn()
        groups = self.search_ldap(
            search_base,
            "(objectClass=group)",
            ['sAMAccountName', 'displayName', 'description', 'member', 'memberOf', 'adminCount', 'whenCreated']
        )
        
        if not groups:
            return []
        
        # Process groups and add member count
        processed_groups = []
        for group in groups:
            members = group.get('member', [])
            group['memberCount'] = len(members) if members else 0
            
            # Add group type based on adminCount
            if group.get('adminCount') == 1:
                group['groupType'] = 'Protected'
            else:
                group['groupType'] = 'Standard'
            
            processed_groups.append(group)
        
        self.print_colored(f"✅ Retrieved {len(processed_groups)} groups", Colors.GREEN)
        return processed_groups

    def get_computers(self) -> List[Dict]:
        """Enumerate computer objects with IP resolution"""
        self.print_colored("🖥️ Enumerating computers...", Colors.MAGENTA)
        
        search_base = self._get_search_base_dn()
        computers = self.search_ldap(
            search_base,
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
        
        search_base = self._get_search_base_dn()
        printers = self.search_ldap(
            search_base,
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

    def try_alternative_user_enumeration(self) -> List[Dict]:
        """Try alternative methods to enumerate users when LDAP fails"""
        self.print_colored("🔄 Attempting alternative user enumeration methods...", Colors.CYAN)
        users = []
        
        # Try net user /dom command
        try:
            self.print_colored("📋 Trying 'net user /dom' command...", Colors.CYAN)
            
            # Build command with credentials if available
            cmd = ['net', 'user', '/dom']
            if self.username and self.password:
                self.print_colored(f"🔐 Using credentials: {self.username}", Colors.CYAN)
                cmd.extend(['/user', self.username, '/password', self.password])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                # Parse net user output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('The command completed') and not line.startswith('User accounts for'):
                        # Extract username from the line
                        username = line.split()[0] if line.split() else None
                        if username and username not in ['User', 'accounts', 'for', '---']:
                            users.append({
                                'sAMAccountName': username,
                                'displayName': username,
                                'source': 'net_user_dom'
                            })
                
                if users:
                    self.print_colored(f"✅ Retrieved {len(users)} users via 'net user /dom'", Colors.GREEN)
                    return users
            else:
                self.print_colored(f"⚠️ 'net user /dom' failed with return code {result.returncode}", Colors.YELLOW, Severity.MEDIUM)
                if result.stderr:
                    self.print_colored(f"Error: {result.stderr.strip()}", Colors.YELLOW, Severity.MEDIUM)
        except Exception as e:
            self.print_colored(f"⚠️ 'net user /dom' failed: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        return users

    def analyze_subnets(self, computers: List[Dict]) -> List[Dict]:
        """Analyze computer IPs and create subnet summaries in /24 format"""
        self.print_colored("🌐 Analyzing network subnets...", Colors.MAGENTA)
        
        subnets = {}
        
        for computer in computers:
            ip = computer.get('ip_address')
            if ip and ip != "Unresolved":
                try:
                    # Parse IP address
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        # Create /24 subnet (first 3 octets)
                        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                        
                        if subnet not in subnets:
                            subnets[subnet] = {
                                'subnet': subnet,
                                'computers': [],
                                'count': 0
                            }
                        
                        subnets[subnet]['computers'].append(computer.get('name', 'Unknown'))
                        subnets[subnet]['count'] += 1
                        
                except Exception as e:
                    self.logger.debug(f"Error parsing IP {ip}: {e}")
                    continue
        
        # Convert to list and sort by numerical value (smaller first)
        subnet_list = list(subnets.values())
        subnet_list.sort(key=lambda x: [int(part) for part in x['subnet'].split('.')[:3]])
        
        return subnet_list


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
        total_all_groups = len(data.get('all_groups', []))
        total_interesting_groups = len(data.get('interesting_groups', []))
        
        # Calculate subnet statistics
        subnets = data.get('subnets', [])
        total_subnets = len(subnets)
        
        # Calculate old logon statistics
        old_logon_users = data.get('old_logon_users', [])
        total_old_logon = len(old_logon_users)
        
        # Calculate old password statistics
        old_password_users = data.get('old_password_users', [])
        total_old_passwords = len(old_password_users)
        
        # Calculate never logon statistics
        never_logon_users = data.get('never_logon_users', [])
        total_never_logon = len(never_logon_users)
        
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
            margin-bottom: 20px;
        }}

        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}

        .info-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }}

        .info-item strong {{
            display: block;
            margin-bottom: 5px;
            color: #3498db;
        }}
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

        /* Enhanced styling for summary items */
        .summary-item {{
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border: 2px solid #dee2e6;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .summary-item:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }}

        .summary-item.high {{
            border-color: #dc3545;
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        }}

        .summary-item.medium {{
            border-color: #ffc107;
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
        }}

        .summary-item.info {{
            border-color: #17a2b8;
            background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
        }}

        .summary-item.success {{
            border-color: #28a745;
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        }}

        /* Status badges for tables */
        .status-badge {{
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .status-enabled {{
            background: #d4edda;
            color: #155724;
        }}

        .status-disabled {{
            background: #f8d7da;
            color: #721c24;
        }}

        .status-yes {{
            background: #d4edda;
            color: #155724;
        }}

        .status-no {{
            background: #f8d7da;
            color: #721c24;
        }}

        /* Days old styling */
        .days-old {{
            font-weight: bold;
        }}

        .days-old.good {{
            color: #28a745;
        }}

        .days-old.warning {{
            color: #ffc107;
        }}

        .days-old.danger {{
            color: #dc3545;
        }}
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
            table-layout: fixed;
        }}
        
        th {{
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            position: relative;
            cursor: pointer;
            user-select: none;
        }}
        
        th:hover {{
            background: linear-gradient(135deg, #0056b3 0%, #004085 100%);
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        
        tr:hover {{
            background-color: #e9ecef;
        }}
        
        .resize-handle {{
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 5px;
            cursor: col-resize;
            background: transparent;
            z-index: 1;
        }}
        
        .resize-handle:hover {{
            background: rgba(255, 255, 255, 0.3);
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
        
        .policy-section {{
            margin: 20px 0;
        }}
        
        .policy-section h4 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .policy-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .policy-table th {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        .policy-table td {{
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .policy-table tr.good {{
            background-color: #d4edda;
            border-left: 4px solid #28a745;
        }}
        
        .policy-table tr.weak {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
        }}
        
        .policy-table tr.neutral {{
            background-color: #f8f9fa;
            border-left: 4px solid #6c757d;
        }}
        
        .policy-table tr:hover {{
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AD Recon Security Report</h1>
            <div class="subtitle">Comprehensive Active Directory Security Analysis</div>
            <div class="scan-info">
                <div class="info-item">
                    <strong>Domain:</strong>
                    {self.domain}
                </div>
                <div class="info-item">
                    <strong>DC IP:</strong>
                    {self.dc_ip}
                </div>
                <div class="info-item">
                    <strong>Scan Date:</strong>
                    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div class="info-item">
                    <strong>Authentication:</strong>
                    {'SIMPLE' if self.username else 'GUEST'} ({self.username or 'Anonymous'})
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="executive-summary">
                <h2 style="color: #2c3e50; margin-bottom: 20px;">📊 Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item high">
                        <div class="summary-number">{high_findings}</div>
                        <div class="summary-label">High Risk Findings</div>
                    </div>
                    <div class="summary-item medium">
                        <div class="summary-number">{medium_findings}</div>
                        <div class="summary-label">Medium Risk Findings</div>
                    </div>
                    <div class="summary-item info">
                        <div class="summary-number">{info_findings}</div>
                        <div class="summary-label">Info Findings</div>
                    </div>
                    <div class="summary-item success">
                        <div class="summary-number">{total_users}</div>
                        <div class="summary-label">Total Users</div>
                    </div>
                    <div class="summary-item success">
                        <div class="summary-number">{total_computers}</div>
                        <div class="summary-label">Computers</div>
                    </div>
                    <div class="summary-item success">
                        <div class="summary-number">{total_domain_admins}</div>
                        <div class="summary-label">Domain Admins</div>
                    </div>
                    <div class="summary-item medium">
                        <div class="summary-number">{total_kerberoast}</div>
                        <div class="summary-label">Kerberoast Candidates</div>
                    </div>
                    <div class="summary-item medium">
                        <div class="summary-number">{total_asrep}</div>
                        <div class="summary-label">AS-REP Candidates</div>
                    </div>
                    <div class="summary-item high">
                        <div class="summary-number">{total_credential_candidates}</div>
                        <div class="summary-label">Potential Passwords</div>
                    </div>
                    <div class="summary-item success">
                        <div class="summary-number">{total_subnets}</div>
                        <div class="summary-label">Network Subnets</div>
                    </div>
                    <div class="summary-item medium">
                        <div class="summary-number">{total_old_logon}</div>
                        <div class="summary-label">Old Logon Users (>180 days)</div>
                    </div>
                    <div class="summary-item medium">
                        <div class="summary-number">{total_old_passwords}</div>
                        <div class="summary-label">Old Password Users (>90 days)</div>
                    </div>
                    <div class="summary-item info">
                        <div class="summary-number">{total_never_logon}</div>
                        <div class="summary-label">Never Logon Users</div>
                    </div>
                    <div class="summary-item success">
                        <div class="summary-number">{total_all_groups}</div>
                        <div class="summary-label">Total Groups</div>
                    </div>
                    <div class="summary-item info">
                        <div class="summary-number">{total_interesting_groups}</div>
                        <div class="summary-label">Interesting Groups</div>
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
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔑 Potential Passwords Found ({total_credential_candidates})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="passwordSearch" placeholder="🔍 Search potential passwords...">
                        </div>
                        {self._generate_credential_table_html(data.get('credential_candidates', []))}
                    </div>
                </div>
            </div>
            ''' if total_credential_candidates > 0 else ''}
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">👑 Domain Admins ({total_domain_admins})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="domainAdminSearch" placeholder="🔍 Search domain admins...">
                        </div>
                        {self._generate_table_html(data.get('domain_admins', []), ['sAMAccountName', 'displayName', 'mail', 'description', 'isDisabled', 'hasPasswordInDesc', 'lastLogonDays', 'passwordAgeDays'])}
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
                        {self._generate_table_html(data.get('users', []), ['sAMAccountName', 'displayName', 'mail', 'description', 'isDisabled', 'hasPasswordInDesc', 'lastLogonDays', 'passwordAgeDays'])}
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
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">⏰ Users with Last Logon > 180 Days ({total_old_logon})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="oldLogonSearch" placeholder="🔍 Search old logon users...">
                        </div>
                        {self._generate_table_html(old_logon_users, ['sAMAccountName', 'displayName', 'userPrincipalName', 'mail', 'lastLogonDays'])}
                    </div>
                </div>
            </div>
            ''' if total_old_logon > 0 else ''}
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔐 Active Users with Old Passwords > 90 Days ({total_old_passwords})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="oldPasswordSearch" placeholder="🔍 Search old password users...">
                        </div>
                        {self._generate_table_html(old_password_users, ['sAMAccountName', 'displayName', 'mail', 'passwordAgeDays'])}
                    </div>
                </div>
            </div>
            ''' if total_old_passwords > 0 else ''}
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🚫 Users Who Never Logged On ({total_never_logon})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="neverLogonSearch" placeholder="🔍 Search never logon users...">
                        </div>
                        {self._generate_table_html(never_logon_users, ['sAMAccountName', 'displayName', 'mail', 'description', 'isDisabled', 'hasPasswordInDesc'])}
                    </div>
                </div>
            </div>
            ''' if total_never_logon > 0 else ''}
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🖥️ Computers ({total_computers})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="computerSearch" placeholder="🔍 Search computers by name, IP, or OS...">
                        </div>
                        {self._generate_table_html(data.get('computers', []), ['name', 'ip_address', 'operatingSystem', 'lastLogon', 'description'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🖨️ Printers ({total_printers})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="printerSearch" placeholder="🔍 Search printers by name, IP, or location...">
                        </div>
                        {self._generate_table_html(data.get('printers', []), ['name', 'ip_address', 'location', 'description'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🏢 Group Policy Objects ({total_gpos})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="gpoSearch" placeholder="🔍 Search GPOs by name or description...">
                        </div>
                        {self._generate_table_html(data.get('gpos', []), ['displayName', 'description', 'gPCFileSysPath', 'whenCreated'])}
                    </div>
                </div>
            </div>
            
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">👥 All Groups ({total_all_groups})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="allGroupsSearch" placeholder="🔍 Search groups by name or description...">
                        </div>
                        {self._generate_table_html(data.get('all_groups', []), ['sAMAccountName', 'displayName', 'description', 'memberCount', 'groupType', 'whenCreated'])}
                    </div>
                </div>
            </div>
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔍 Interesting Groups ({total_interesting_groups})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="interestingGroupsSearch" placeholder="🔍 Search interesting groups...">
                        </div>
                        {self._generate_table_html(data.get('interesting_groups', []), ['sAMAccountName', 'displayName', 'description', 'memberCount', 'groupType'])}
                    </div>
                </div>
            </div>
            ''' if total_interesting_groups > 0 else ''}
            

            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔐 Password Policy</h2>
                    <div class="section-content">
                        {self._generate_password_policy_html(data.get('password_policy', {}))}
                    </div>
                </div>
            </div>
            ''' if data.get('password_policy') else ''}
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🌐 Network Subnets ({total_subnets})</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="subnetSearch" placeholder="🔍 Search subnets by IP range...">
                        </div>
                        {self._generate_subnet_table_html(subnets)}
                    </div>
                </div>
            </div>
            ''' if total_subnets > 0 else ''}

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
            
            // Enhanced search functionality with live result count
            function setupSearch(searchBoxId) {{
                const searchBox = document.getElementById(searchBoxId);
                if (!searchBox) return;
                
                // Create result count display
                const resultCount = document.createElement('div');
                resultCount.className = 'search-result-count';
                resultCount.style.cssText = 'margin-top: 10px; font-size: 0.9em; color: #666; font-style: italic;';
                searchBox.parentNode.appendChild(resultCount);
                
                function updateResultCount() {{
                    const input = searchBox.value.toLowerCase();
                    const dataSection = searchBox.closest('.data-section');
                    if (!dataSection) return;
                    
                    const table = dataSection.querySelector('table');
                    if (!table) return;
                    
                    const rows = table.getElementsByTagName('tr');
                    let visibleCount = 0;
                    
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
                        if (found) visibleCount++;
                    }}
                    
                    // Update result count display
                    const totalRows = rows.length - 1; // Exclude header
                    if (input === '') {{
                        resultCount.textContent = `Showing all ${{totalRows}} items`;
                    }} else {{
                        resultCount.textContent = `Found ${{visibleCount}} of ${{totalRows}} items`;
                    }}
                }}
                
                searchBox.addEventListener('keyup', updateResultCount);
                searchBox.addEventListener('input', updateResultCount);
                
                            // Initialize count on page load
            setTimeout(updateResultCount, 100);
        }}
        
        // Initialize all sections as collapsed by default
        document.addEventListener('DOMContentLoaded', function() {{
            const sections = document.querySelectorAll('.collapsible-section');
            sections.forEach(section => {{
                const content = section.querySelector('.section-content');
                const header = section.querySelector('.section-header');
                if (content && header) {{
                    content.classList.add('collapsed');
                    header.classList.add('collapsed');
                }}
            }});
        }});
        
        // Column sorting functionality
            function setupTableSorting() {{
                const tables = document.querySelectorAll('table');
                tables.forEach(table => {{
                    const headers = table.querySelectorAll('th');
                    headers.forEach((header, index) => {{
                        header.style.cursor = 'pointer';
                        header.style.userSelect = 'none';
                        header.style.position = 'relative';
                        
                        // Add sort indicators
                        const sortIndicator = document.createElement('span');
                        sortIndicator.innerHTML = ' ↕️';
                        sortIndicator.style.fontSize = '0.8em';
                        sortIndicator.style.marginLeft = '5px';
                        header.appendChild(sortIndicator);
                        
                        header.addEventListener('click', () => {{
                            const rows = Array.from(table.querySelectorAll('tbody tr')).filter(row => row.style.display !== 'none');
                            const currentOrder = header.getAttribute('data-sort') || 'none';
                            
                            // Clear other headers
                            headers.forEach(h => {{
                                h.setAttribute('data-sort', 'none');
                                h.querySelector('span').innerHTML = ' ↕️';
                            }});
                            
                            // Set new order
                            const newOrder = currentOrder === 'asc' ? 'desc' : 'asc';
                            header.setAttribute('data-sort', newOrder);
                            header.querySelector('span').innerHTML = newOrder === 'asc' ? ' ↑' : ' ↓';
                            
                            // Sort rows
                            rows.sort((a, b) => {{
                                const aText = a.cells[index].textContent.trim();
                                const bText = b.cells[index].textContent.trim();
                                
                                // Try to parse as numbers first
                                const aNum = parseFloat(aText);
                                const bNum = parseFloat(bText);
                                
                                if (!isNaN(aNum) && !isNaN(bNum)) {{
                                    return newOrder === 'asc' ? aNum - bNum : bNum - aNum;
                                }}
                                
                                // Sort as strings
                                return newOrder === 'asc' ? 
                                    aText.localeCompare(bText) : 
                                    bText.localeCompare(aText);
                            }});
                            
                            // Reorder rows
                            const tbody = table.querySelector('tbody');
                            rows.forEach(row => tbody.appendChild(row));
                        }});
                    }});
                }});
            }}
            
            // Column resizing functionality
            function setupColumnResizing() {{
                const tables = document.querySelectorAll('table');
                tables.forEach(table => {{
                    const headers = table.querySelectorAll('th');
                    headers.forEach((header, index) => {{
                        // Add resize handle
                        const resizeHandle = document.createElement('div');
                        resizeHandle.className = 'resize-handle';
                        header.appendChild(resizeHandle);
                        
                        let isResizing = false;
                        let startX, startWidth;
                        
                        resizeHandle.addEventListener('mousedown', (e) => {{
                            isResizing = true;
                            startX = e.clientX;
                            startWidth = header.offsetWidth;
                            e.preventDefault();
                        }});
                        
                        document.addEventListener('mousemove', (e) => {{
                            if (!isResizing) return;
                            
                            const deltaX = e.clientX - startX;
                            const newWidth = Math.max(50, startWidth + deltaX);
                            
                            // Set width for all cells in this column
                            const rows = table.querySelectorAll('tr');
                            rows.forEach(row => {{
                                const cell = row.cells[index];
                                if (cell) {{
                                    cell.style.width = newWidth + 'px';
                                    cell.style.minWidth = newWidth + 'px';
                                }}
                            }});
                        }});
                        
                        document.addEventListener('mouseup', () => {{
                            isResizing = false;
                        }});
                    }});
                }});
            }}
            
            // Setup searches
            setupSearch('userSearch');
            setupSearch('passwordSearch');
            setupSearch('oldLogonSearch');
            setupSearch('oldPasswordSearch');
            setupSearch('neverLogonSearch');
            setupSearch('computerSearch');
            setupSearch('printerSearch');
            setupSearch('gpoSearch');
            setupSearch('subnetSearch');
            setupSearch('domainAdminSearch');
            setupSearch('allGroupsSearch');
            setupSearch('interestingGroupsSearch');
            
            // Setup table sorting and resizing
            setupTableSorting();
            setupColumnResizing();
            
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
                        {html.escape(finding.description).replace('\n', '<br>')}
                    </div>
                    <div class="finding-meta">
                        📁 Category: {finding.category} | ⏰ Time: {finding.timestamp}
                    </div>
                </div>
            """)
        
        return ''.join(html_parts)

    def _generate_table_html(self, data: List[Dict], columns: List[str]) -> str:
        """Generate HTML table from data with enhanced styling"""
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
                
                # Apply enhanced styling for different column types
                if col == 'isDisabled':
                    if value == 'Disabled':
                        value = '<span class="status-badge status-disabled">Disabled</span>'
                    elif value == 'Enabled':
                        value = '<span class="status-badge status-enabled">Enabled</span>'
                    else:
                        value = html.escape(str(value))
                elif col == 'hasPasswordInDesc':
                    if value == 'Yes':
                        value = '<span class="status-badge status-yes">Yes</span>'
                    elif value == 'No':
                        value = '<span class="status-badge status-no">No</span>'
                    else:
                        value = html.escape(str(value))
                elif col == 'lastLogonDays':
                    if value in ['Never', 'Unknown']:
                        value = f'<span class="days-old danger">{value}</span>'
                    else:
                        try:
                            days = int(value)
                            if days < 90:
                                value = f'<span class="days-old good">{value}</span>'
                            elif days < 180:
                                value = f'<span class="days-old warning">{value}</span>'
                            else:
                                value = f'<span class="days-old danger">{value}</span>'
                        except ValueError:
                            value = html.escape(str(value))
                elif col == 'passwordAgeDays':
                    if value in ['Never', 'Unknown']:
                        value = f'<span class="days-old danger">{value}</span>'
                    else:
                        try:
                            days = int(value)
                            if days < 90:
                                value = f'<span class="days-old good">{value}</span>'
                            elif days < 180:
                                value = f'<span class="days-old warning">{value}</span>'
                            else:
                                value = f'<span class="days-old danger">{value}</span>'
                        except ValueError:
                            value = html.escape(str(value))
                else:
                    value = html.escape(str(value))
                
                html_parts.append(f'<td>{value}</td>')
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
                    r'([a-zA-Z0-9!@#$%^&*()_+-=[]{}|;:,.<>?]{8,})',  # 8+ chars with special chars
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, description, re.IGNORECASE)
                    # Filter out common false positives
                    filtered_matches = []
                    for match in matches:
                        match_lower = match.lower()
                        if not any(fp in match_lower for fp in ['built-in', 'computer', 'domain', 'account', 'user']):
                            filtered_matches.append(match)
                    potential_creds.extend(filtered_matches)
            
            potential_creds_str = ', '.join(set(potential_creds)) if potential_creds else 'None detected'
            
            html_parts.append(f'<tr>')
            html_parts.append(f'<td>{html.escape(username)}</td>')
            html_parts.append(f'<td>{html.escape(description)}</td>')
            html_parts.append(f'<td>{html.escape(potential_creds_str)}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return ''.join(html_parts)

    def _generate_subnet_table_html(self, subnets: List[Dict]) -> str:
        """Generate HTML table for subnet data"""
        if not subnets:
            return '<div class="no-data">No subnets found.</div>'
        
        html_content = '<table><thead><tr><th>Subnet</th><th>Computer Count</th><th>Computers</th></tr></thead><tbody>'
        
        for subnet_data in subnets:
            subnet = subnet_data['subnet']
            count = subnet_data['count']
            computers = ', '.join(subnet_data['computers'])
            
            html_content += f'<tr><td>{html.escape(subnet)}</td><td>{count}</td><td>{html.escape(computers)}</td></tr>'
        
        html_content += '</tbody></table>'
        return html_content

    def _generate_password_policy_html(self, policy: Dict[str, Any]) -> str:
        """Generate HTML table for password policy data"""
        if not policy:
            return '<div class="no-data">Password policy not available.</div>'
        
        html_content = '''
        <div class="policy-section">
            <h4>Domain Password Policy Settings</h4>
            <table class="policy-table">
                <thead>
                    <tr>
                        <th>Setting</th>
                        <th>Value</th>
                        <th>Security Assessment</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        # Define policy settings with security assessments
        policy_settings = [
            ('Minimum Password Length', policy.get('minPwdLength', 'Unknown'), 
             '✅ Good' if policy.get('minPwdLength', 0) >= 8 else '⚠️ Weak - should be 8+ characters'),
            ('Maximum Password Age', f"{policy.get('maxPwdAge', 'Unknown')} days" if policy.get('maxPwdAge') != "Never" else "Never", 
             '✅ Good' if policy.get('maxPwdAge') == "Never" or (isinstance(policy.get('maxPwdAge'), int) and policy.get('maxPwdAge') <= 90) else '⚠️ Weak - should be 90 days or less'),
            ('Minimum Password Age', f"{policy.get('minPwdAge', 'Unknown')} days", 
             '✅ Good'),
            ('Password History Length', policy.get('pwdHistoryLength', 'Unknown'), 
             '✅ Good' if policy.get('pwdHistoryLength', 0) >= 5 else '⚠️ Weak - should be 5+ passwords'),
            ('Account Lockout Threshold', policy.get('lockoutThreshold', 'Unknown'), 
             '✅ Good' if policy.get('lockoutThreshold', 0) > 0 and policy.get('lockoutThreshold', 0) <= 10 else '⚠️ Weak - should be 5-10 attempts'),
            ('Account Lockout Duration', f"{policy.get('lockoutDuration', 'Unknown')} minutes" if policy.get('lockoutDuration') != "Never" else "Never", 
             '✅ Good' if policy.get('lockoutDuration') == "Never" or (isinstance(policy.get('lockoutDuration'), int) and policy.get('lockoutDuration') >= 15) else '⚠️ Weak - should be 15+ minutes'),
            ('Lockout Observation Window', policy.get('lockoutObservationWindow', 'Unknown'), 
             '✅ Good')
        ]
        
        for setting, value, assessment in policy_settings:
            assessment_class = 'good' if '✅' in assessment else 'weak' if '⚠️' in assessment else 'neutral'
            html_content += f'''
                <tr class="{assessment_class}">
                    <td><strong>{html.escape(setting)}</strong></td>
                    <td>{html.escape(str(value))}</td>
                    <td>{html.escape(assessment)}</td>
                </tr>
            '''
        
        html_content += '''
                </tbody>
            </table>
        </div>
        '''
        
        return html_content

    def _has_password_pattern(self, description: str) -> bool:
        """Check if description contains password pattern"""
        if not description:
            return False
        
        # Skip false positives - filter out built-in accounts and computer/domain patterns
        description_lower = description.lower()
        if any(pattern in description_lower for pattern in ['built-in account', 'computer/domain']):
            return False
        
        # Check if description meets credential criteria
        if len(description) >= 6:
            has_upper = any(c.isupper() for c in description)
            has_lower = any(c.islower() for c in description)
            has_digit = any(c.isdigit() for c in description)
            has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in description)
            
            type_count = sum([has_upper, has_lower, has_digit, has_special])
            
            # Rule 1: ≥6 chars, contains ≥3 types: upper/lower/digit/special
            # Rule 2: ≥6 chars, must include special characters + 1 more type
            if type_count >= 3 or (has_special and sum([has_upper, has_lower, has_digit]) >= 1):
                return True
        
        return False

    def _calculate_last_logon_days(self, last_logon) -> str:
        """Calculate days since last logon"""
        if not last_logon:
            return "Never"
        
        try:
            if isinstance(last_logon, str):
                # Check for never logon dates (1601-01-01)
                if '1601-01-01' in last_logon:
                    return "Never"
                
                # Handle different date formats
                if 'Z' in last_logon:
                    last_logon_date = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                elif '+' in last_logon and '.' in last_logon:
                    # Handle format like "2025-08-03 10:07:37.466476+00:00"
                    # Remove microseconds and parse
                    try:
                        # Split by '.' to separate microseconds
                        parts = last_logon.split('.')
                        if len(parts) >= 2:
                            base_time = parts[0]  # "2025-08-03 10:07:37"
                            # Extract timezone from the microseconds part
                            micro_tz = parts[1]  # "466476+00:00"
                            if '+' in micro_tz:
                                timezone_part = '+' + micro_tz.split('+')[1]  # "+00:00"
                            else:
                                timezone_part = '+00:00'
                            clean_time = base_time + timezone_part
                            last_logon_date = datetime.fromisoformat(clean_time)
                        else:
                            last_logon_date = datetime.fromisoformat(last_logon)
                    except:
                        # Fallback to simple parsing
                        last_logon_date = datetime.fromisoformat(last_logon)
                else:
                    last_logon_date = datetime.fromisoformat(last_logon)
            else:
                last_logon_date = last_logon
            
            # Make current time timezone-aware to match the parsed date
            from datetime import timezone
            current_time = datetime.now(timezone.utc)
            days_diff = (current_time - last_logon_date).days
            return str(days_diff)
        except Exception as e:
            self.logger.debug(f"Error parsing last logon date {last_logon}: {e}")
            return "Unknown"

    def _calculate_password_age_days(self, pwd_last_set) -> str:
        """Calculate days since last password change"""
        if not pwd_last_set:
            return "Never"
        
        try:
            if isinstance(pwd_last_set, str):
                # Handle different date formats
                if 'Z' in pwd_last_set:
                    pwd_date = datetime.fromisoformat(pwd_last_set.replace('Z', '+00:00'))
                elif '+' in pwd_last_set and '.' in pwd_last_set:
                    # Handle format like "2025-08-03 10:07:37.466476+00:00"
                    # Remove microseconds and parse
                    try:
                        # Split by '.' to separate microseconds
                        parts = pwd_last_set.split('.')
                        if len(parts) >= 2:
                            base_time = parts[0]  # "2025-08-03 10:07:37"
                            # Extract timezone from the microseconds part
                            micro_tz = parts[1]  # "466476+00:00"
                            if '+' in micro_tz:
                                timezone_part = '+' + micro_tz.split('+')[1]  # "+00:00"
                            else:
                                timezone_part = '+00:00'
                            clean_time = base_time + timezone_part
                            pwd_date = datetime.fromisoformat(clean_time)
                        else:
                            pwd_date = datetime.fromisoformat(pwd_last_set)
                    except:
                        # Fallback to simple parsing
                        pwd_date = datetime.fromisoformat(pwd_last_set)
                else:
                    pwd_date = datetime.fromisoformat(pwd_last_set)
            else:
                pwd_date = pwd_last_set
            
            # Make current time timezone-aware to match the parsed date
            from datetime import timezone
            current_time = datetime.now(timezone.utc)
            days_diff = (current_time - pwd_date).days
            return str(days_diff)
        except Exception as e:
            self.logger.debug(f"Error parsing password date {pwd_last_set}: {e}")
            return "Unknown"

    def get_users_with_old_passwords(self, users: List[Dict], days_threshold: int = 90) -> List[Dict]:
        """Get active users with passwords older than specified days"""
        old_password_users = []
        
        for user in users:
            password_age_days = user.get('passwordAgeDays')
            if password_age_days and password_age_days != "Never" and password_age_days != "Unknown":
                try:
                    days = int(password_age_days)
                    if days > days_threshold and user.get('isDisabled') == 'Enabled':
                        old_password_users.append(user)
                except ValueError:
                    continue
        
        return old_password_users

    def analyze_user_activity_risks(self, users: List[Dict]):
        """Analyze users for activity-based security risks"""
        old_password_users = self.get_users_with_old_passwords(users, 90)
        old_logon_users = self.get_users_with_old_logon(users, 180)
        never_logon_users = self.get_users_never_logon(users)
        
        # Analyze old passwords
        if old_password_users:
            old_password_list = [f"• {user.get('sAMAccountName')} ({user.get('passwordAgeDays')} days)" for user in old_password_users]
            self.add_finding(Severity.MEDIUM, "Password Security", 
                           "Users with old passwords (>90 days)",
                           f"Multiple active users have not changed their passwords in over 90 days:\n" + "\n".join(old_password_list) +
                           "\n\n**Why this is risky:** Old passwords increase the risk of credential compromise. Users may have forgotten their passwords, making them more likely to use weak passwords or write them down." +
                           "\n\n**How attackers can exploit this:** Attackers can target these accounts for password spraying, brute force attacks, or social engineering. Old passwords are more likely to be weak or reused across systems.")
        
        # Analyze old logon times
        if old_logon_users:
            old_logon_list = [f"• {user.get('sAMAccountName')} ({user.get('lastLogonDays')} days)" for user in old_logon_users]
            self.add_finding(Severity.MEDIUM, "Account Management", 
                           "Users with old last logon (>180 days)",
                           f"Multiple active users have not logged on in over 180 days:\n" + "\n".join(old_logon_list) +
                           "\n\n**Why this is risky:** Inactive accounts may be forgotten by administrators and users, making them prime targets for attackers. These accounts may have weak passwords or outdated security settings." +
                           "\n\n**How attackers can exploit this:** Attackers can target inactive accounts for password spraying or brute force attacks, as these accounts are less likely to be monitored or have strong passwords.")
        
        # Analyze never logon users
        if never_logon_users:
            never_logon_list = [f"• {user.get('sAMAccountName')}" for user in never_logon_users]
            self.add_finding(Severity.MEDIUM, "Account Management", 
                           "Users who never logged on",
                           f"Multiple users have never logged on to the domain:\n" + "\n".join(never_logon_list) +
                           "\n\n**Why this is risky:** Never-used accounts may have default passwords, weak passwords, or be forgotten by administrators. These accounts provide an easy entry point for attackers." +
                           "\n\n**How attackers can exploit this:** Attackers can target these accounts with default password lists, common passwords, or password spraying attacks, as they are likely to have weak or default credentials.")
        
        # Analyze service accounts
        service_accounts = []
        for user in users:
            username = user.get('sAMAccountName', '').lower()
            if any(keyword in username for keyword in ['svc', 'service', 'admin', 'backup', 'sql', 'web', 'app']):
                if user.get('isDisabled') == 'Enabled':
                    service_accounts.append(user)
        
        if service_accounts:
            service_list = [f"• {user.get('sAMAccountName')}" for user in service_accounts]
            self.add_finding(Severity.HIGH, "Service Account Security", 
                           "Service accounts identified",
                           f"Multiple service accounts found in the domain:\n" + "\n".join(service_list) +
                           "\n\n**Why this is risky:** Service accounts often have elevated privileges and are used for automated tasks. They may have weak passwords, never expire, or be used across multiple systems." +
                           "\n\n**How attackers can exploit this:** Attackers can target service accounts for privilege escalation, lateral movement, or persistence. Service accounts often have access to multiple systems and may have elevated permissions.")
        
        # Analyze accounts with SPNs (Kerberoasting)
        spn_accounts = []
        for user in users:
            if user.get('servicePrincipalName'):
                spn_accounts.append(user)
        
        if spn_accounts:
            spn_list = [f"• {user.get('sAMAccountName')} - {user.get('servicePrincipalName')}" for user in spn_accounts]
            self.add_finding(Severity.HIGH, "Kerberoasting", 
                           "Accounts with Service Principal Names",
                           f"Multiple accounts have Service Principal Names (SPNs) configured:\n" + "\n".join(spn_list) +
                           "\n\n**Why this is risky:** Accounts with SPNs are vulnerable to Kerberoasting attacks. Attackers can request service tickets for these accounts and attempt to crack the passwords offline." +
                           "\n\n**How attackers can exploit this:** Attackers can use tools like Rubeus, Impacket, or Mimikatz to perform Kerberoasting attacks, potentially cracking weak passwords without triggering account lockouts.")
        
        # Analyze accounts with adminCount=1
        admin_count_users = []
        for user in users:
            if user.get('adminCount') == 1:
                admin_count_users.append(user)
        
        if admin_count_users:
            admin_list = [f"• {user.get('sAMAccountName')}" for user in admin_count_users]
            self.add_finding(Severity.HIGH, "Privileged Accounts", 
                           "Accounts with adminCount=1",
                           f"Multiple accounts have adminCount=1 attribute:\n" + "\n".join(admin_list) +
                           "\n\n**Why this is risky:** The adminCount=1 attribute indicates these accounts are protected by the AdminSDHolder process and have elevated privileges. This creates a larger attack surface for privilege escalation." +
                           "\n\n**How attackers can exploit this:** Attackers can target these accounts for privilege escalation attacks, password spraying, or lateral movement. Compromising any of these accounts provides elevated access to the domain.")

    def get_users_with_old_logon(self, users: List[Dict], days_threshold: int = 180) -> List[Dict]:
        """Get users with last logon older than specified days"""
        old_logon_users = []
        
        for user in users:
            last_logon_days = user.get('lastLogonDays')
            if last_logon_days and last_logon_days != "Never" and last_logon_days != "Unknown":
                try:
                    days = int(last_logon_days)
                    if days > days_threshold and user.get('isDisabled') == 'Enabled':
                        old_logon_users.append(user)
                except ValueError:
                    continue
        
        return old_logon_users

    def get_users_never_logon(self, users: List[Dict]) -> List[Dict]:
        """Get users who never logged on"""
        never_logon_users = []
        
        for user in users:
            last_logon_days = user.get('lastLogonDays')
            if last_logon_days == "Never":
                never_logon_users.append(user)
        
        return never_logon_users

    def get_password_policy(self) -> Dict[str, Any]:
        """Retrieve domain password policy"""
        self.print_colored("🔐 Retrieving domain password policy...", Colors.MAGENTA)
        
        try:
            # Get domain object
            search_base = self._get_search_base_dn()
            domain_info = self.search_ldap(
                search_base,
                "(objectClass=domain)",
                ['minPwdLength', 'maxPwdAge', 'minPwdAge', 'pwdHistoryLength', 
                 'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow']
            )
            
            if domain_info:
                policy = domain_info[0]
                
                # Convert maxPwdAge from negative seconds to days
                max_pwd_age = policy.get('maxPwdAge')
                if max_pwd_age and max_pwd_age != 0:
                    max_pwd_age_days = abs(max_pwd_age) // (24 * 60 * 60 * 10000000)  # Convert to days
                else:
                    max_pwd_age_days = "Never"
                
                # Convert minPwdAge from negative seconds to days
                min_pwd_age = policy.get('minPwdAge')
                if min_pwd_age and min_pwd_age != 0:
                    min_pwd_age_days = abs(min_pwd_age) // (24 * 60 * 60 * 10000000)  # Convert to days
                else:
                    min_pwd_age_days = 0
                
                # Convert lockout duration from negative seconds to minutes
                lockout_duration = policy.get('lockoutDuration')
                if lockout_duration and lockout_duration != 0:
                    lockout_duration_minutes = abs(lockout_duration) // (60 * 10000000)  # Convert to minutes
                else:
                    lockout_duration_minutes = "Never"
                
                password_policy = {
                    'minPwdLength': policy.get('minPwdLength', 'Unknown'),
                    'maxPwdAge': max_pwd_age_days,
                    'minPwdAge': min_pwd_age_days,
                    'pwdHistoryLength': policy.get('pwdHistoryLength', 'Unknown'),
                    'pwdProperties': policy.get('pwdProperties', 'Unknown'),
                    'lockoutThreshold': policy.get('lockoutThreshold', 'Unknown'),
                    'lockoutDuration': lockout_duration_minutes,
                    'lockoutObservationWindow': policy.get('lockoutObservationWindow', 'Unknown')
                }
                
                # Analyze password policy for risks
                self._analyze_password_policy_risks(password_policy)
                
                return password_policy
            else:
                self.print_colored("⚠️ Could not retrieve password policy", Colors.YELLOW, Severity.MEDIUM)
                return {}
                
        except Exception as e:
            self.print_colored(f"⚠️ Failed to retrieve password policy: {e}", Colors.YELLOW, Severity.MEDIUM)
            return {}

    def _analyze_password_policy_risks(self, policy: Dict[str, Any]):
        """Analyze password policy for security risks"""
        risks = []
        
        # Check minimum password length
        min_length = policy.get('minPwdLength')
        if min_length and min_length < 8:
            risks.append(f"Minimum password length is only {min_length} characters (recommended: 8+)")
        
        # Check maximum password age
        max_age = policy.get('maxPwdAge')
        if max_age == "Never":
            risks.append("Passwords never expire - users may use weak passwords indefinitely")
        elif isinstance(max_age, int) and max_age > 365:
            risks.append(f"Passwords expire after {max_age} days (recommended: 90 days or less)")
        
        # Check password history
        history_length = policy.get('pwdHistoryLength')
        if history_length and history_length < 5:
            risks.append(f"Password history only keeps {history_length} previous passwords (recommended: 5+)")
        
        # Check lockout threshold
        lockout_threshold = policy.get('lockoutThreshold')
        if lockout_threshold == 0:
            risks.append("No account lockout policy - brute force attacks are not prevented")
        elif isinstance(lockout_threshold, int) and lockout_threshold > 10:
            risks.append(f"Account lockout threshold is {lockout_threshold} attempts (recommended: 5-10)")
        
        # Check lockout duration
        lockout_duration = policy.get('lockoutDuration')
        if lockout_duration == "Never":
            risks.append("Account lockout duration is unlimited - accounts remain locked indefinitely")
        elif isinstance(lockout_duration, int) and lockout_duration < 15:
            risks.append(f"Account lockout duration is only {lockout_duration} minutes (recommended: 15-30 minutes)")
        
        # Add findings for password policy risks
        if risks:
            self.add_finding(Severity.HIGH, "Password Policy", 
                           "Weak password policy configuration",
                           f"Domain password policy has multiple security weaknesses:\n" + "\n".join([f"• {risk}" for risk in risks]) +
                           "\n\n**Why this is risky:** Weak password policies make it easier for attackers to crack passwords through brute force or dictionary attacks." +
                           "\n\n**How attackers can exploit this:** Attackers can use automated tools to guess passwords, and weak policies reduce the time and effort required to compromise accounts.")
        else:
            self.add_finding(Severity.INFO, "Password Policy", 
                           "Password policy appears secure",
                           "Domain password policy follows security best practices with appropriate length, age, and lockout settings.")

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
        
        # Generate username list for password spraying
        if users:
            usernames = [user.get('sAMAccountName', '') for user in users if user.get('sAMAccountName')]
            self.save_txt(usernames, 'usernames.txt')
            self.print_colored(f"💾 Username list saved: {len(usernames)} usernames", Colors.GREEN)
        
        self.print_colored(f"✅ Guest mode completed. Results saved to: {output_folder}", Colors.GREEN)
        return True

    def run_full_mode(self):
        """Run comprehensive reconnaissance in full mode with permission error handling"""
        self.print_colored("🔍 Starting full mode reconnaissance...", Colors.BLUE)
        
        # Create output folder at the beginning
        output_folder = self.create_output_folder()
        self.print_colored(f"📁 Output folder created: {output_folder}", Colors.CYAN)
        
        # Try LDAP connection first
        ldap_connected = self.connect_ldap("full")
        if not ldap_connected:
            self.print_colored("⚠️ LDAP authentication failed, attempting alternative methods...", Colors.YELLOW, Severity.MEDIUM)
        
        # Initialize data containers
        domain_admins = []
        users = []
        credential_candidates = []
        kerberoast_candidates = []
        asrep_candidates = []
        gpos = []
        computers = []
        printers = []
        
        # Try to enumerate domain admins
        if ldap_connected:
            try:
                self.print_colored("👑 Attempting to enumerate Domain Admins...", Colors.CYAN)
                domain_admins = self.get_domain_admins()
                if domain_admins:
                    self.print_colored(f"✅ Retrieved {len(domain_admins)} domain admins", Colors.GREEN)
                    # Save domain admins immediately
                    admin_names = [admin.get('sAMAccountName') for admin in domain_admins]
                    self.save_txt(admin_names, 'domain_admins.txt')
                    self.print_colored("💾 Domain admins saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ No domain admins found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate domain admins: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping domain admin enumeration - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate all users
        if ldap_connected:
            try:
                self.print_colored("👥 Attempting to enumerate all users via LDAP...", Colors.CYAN)
                users = self.get_all_users()
                if users:
                    self.print_colored(f"✅ Retrieved {len(users)} users via LDAP", Colors.GREEN)
                    # Save users immediately
                    self.save_json(users, 'all_users.json')
                    self.print_colored("💾 Users data saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ No users found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate users via LDAP: {e}", Colors.YELLOW, Severity.MEDIUM)
                # Try alternative enumeration methods
                users = self.try_alternative_user_enumeration()
                if users:
                    self.save_json(users, 'all_users.json')
                    self.print_colored("💾 Users data (alternative method) saved incrementally", Colors.GREEN)
        else:
            self.print_colored("👥 Attempting to enumerate users via alternative methods...", Colors.CYAN)
            users = self.try_alternative_user_enumeration()
            if users:
                self.save_json(users, 'all_users.json')
                self.print_colored("💾 Users data (alternative method) saved incrementally", Colors.GREEN)
        
        # Try to analyze descriptions for credentials
        if users:
            try:
                self.print_colored("🔎 Analyzing user descriptions for credentials...", Colors.CYAN)
                credential_candidates = self.analyze_descriptions(users)
                if credential_candidates:
                    self.print_colored(f"✅ Found {len(credential_candidates)} credential candidates", Colors.GREEN)
                    # Save credential candidates immediately
                    self.save_txt(credential_candidates, 'password_candidates.txt')
                    self.print_colored("💾 Credential candidates saved incrementally", Colors.GREEN)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to analyze descriptions: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to find Kerberoasting candidates
        if users:
            try:
                self.print_colored("🍗 Searching for Kerberoasting candidates...", Colors.CYAN)
                kerberoast_candidates = self.get_kerberoast_candidates(users)
                if kerberoast_candidates:
                    self.print_colored(f"✅ Found {len(kerberoast_candidates)} Kerberoasting candidates", Colors.GREEN)
                    # Save kerberoast candidates immediately
                    kerberoast_names = [candidate.get('sAMAccountName') for candidate in kerberoast_candidates]
                    self.save_txt(kerberoast_names, 'kerberoast_candidates.txt')
                    self.print_colored("💾 Kerberoasting candidates saved incrementally", Colors.GREEN)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to find Kerberoasting candidates: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to find AS-REP candidates
        if users:
            try:
                self.print_colored("🔐 Searching for AS-REP roastable users...", Colors.CYAN)
                asrep_candidates = self.get_asrep_candidates(users)
                if asrep_candidates:
                    self.print_colored(f"✅ Found {len(asrep_candidates)} AS-REP candidates", Colors.GREEN)
                    # Save AS-REP candidates immediately
                    asrep_names = [candidate.get('sAMAccountName') for candidate in asrep_candidates]
                    self.save_txt(asrep_names, 'asrep_candidates.txt')
                    self.print_colored("💾 AS-REP candidates saved incrementally", Colors.GREEN)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to find AS-REP candidates: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate GPOs
        if ldap_connected:
            try:
                self.print_colored("🏢 Attempting to enumerate Group Policy Objects...", Colors.CYAN)
                gpos = self.get_gpos()
                if gpos:
                    self.print_colored(f"✅ Retrieved {len(gpos)} GPOs", Colors.GREEN)
                    # Save GPOs immediately
                    self.save_json(gpos, 'gpos.json')
                    self.print_colored("💾 GPOs data saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ No GPOs found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate GPOs: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping GPO enumeration - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate all groups
        all_groups = []
        if ldap_connected:
            try:
                self.print_colored("👥 Attempting to enumerate all groups...", Colors.CYAN)
                all_groups = self.get_all_groups()
                if all_groups:
                    self.print_colored(f"✅ Retrieved {len(all_groups)} groups", Colors.GREEN)
                    # Save groups immediately
                    self.save_json(all_groups, 'all_groups.json')
                    self.print_colored("💾 Groups data saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ No groups found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate groups: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping group enumeration - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate all groups and find missing users (always try to find missing users)
        missing_users = []
        if ldap_connected and users:
            try:
                self.print_colored(f"🔍 Found {len(users)} users via LDAP, attempting group enumeration to find missing users...", Colors.CYAN)
                
                # Use all groups instead of just interesting groups
                if all_groups:
                    self.print_colored(f"✅ Using {len(all_groups)} groups to find missing users", Colors.GREEN)
                    
                    # Resolve group members to find missing users and merge them into main users list
                    try:
                        self.print_colored("🔍 Resolving group members to find missing users...", Colors.CYAN)
                        missing_users, failed_lookups = self.resolve_group_members(all_groups, users)
                        
                        if failed_lookups:
                            # Save failed lookups to separate file (hidden from report)
                            self.save_txt(failed_lookups, 'failed_user_lookups.txt')
                            self.print_colored(f"⚠️ {len(failed_lookups)} user lookups failed (saved to failed_user_lookups.txt)", Colors.YELLOW, Severity.MEDIUM)
                        
                        if missing_users:
                            self.print_colored(f"✅ Found {len(missing_users)} additional users from group enumeration", Colors.GREEN)
                            
                            # Merge missing users into main users list
                            existing_usernames = {user.get('sAMAccountName') for user in users}
                            for missing_user in missing_users:
                                if missing_user.get('sAMAccountName') not in existing_usernames:
                                    users.append(missing_user)
                            
                            self.print_colored(f"✅ Merged {len(missing_users)} users into main users list (total: {len(users)})", Colors.GREEN)
                            
                            # Re-analyze all users together for credentials
                            try:
                                self.print_colored("🔎 Re-analyzing all users for credentials...", Colors.CYAN)
                                all_user_credentials = self.analyze_descriptions(users)
                                if all_user_credentials:
                                    self.print_colored(f"✅ Found {len(all_user_credentials)} total credential candidates", Colors.GREEN)
                                    # Update credential candidates
                                    credential_candidates = all_user_credentials
                                    # Save updated credential candidates
                                    self.save_txt(credential_candidates, 'password_candidates.txt')
                                    self.print_colored("💾 Updated credential candidates saved", Colors.GREEN)
                            except Exception as e:
                                self.print_colored(f"⚠️ Failed to re-analyze user descriptions: {e}", Colors.YELLOW, Severity.MEDIUM)
                    except Exception as e:
                        self.print_colored(f"⚠️ Failed to resolve group members: {e}", Colors.YELLOW, Severity.MEDIUM)
                else:
                    self.print_colored("⚠️ No groups found", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate groups: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping group enumeration - LDAP not connected or no users found", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate computers
        if ldap_connected:
            try:
                self.print_colored("🖥️ Attempting to enumerate computers...", Colors.CYAN)
                computers = self.get_computers()
                if computers:
                    self.print_colored(f"✅ Retrieved {len(computers)} computers", Colors.GREEN)
                    # Save computers immediately
                    self.save_csv(computers, 'computers_with_ips.csv')
                    self.print_colored("💾 Computers data saved incrementally", Colors.GREEN)
                    
                    # Analyze subnets from computer IPs
                    try:
                        self.print_colored("🌐 Analyzing network subnets...", Colors.CYAN)
                        subnets = self.analyze_subnets(computers)
                        if subnets:
                            self.print_colored(f"✅ Found {len(subnets)} unique subnets", Colors.GREEN)
                            # Save subnets immediately
                            self.save_json(subnets, 'subnets.json')
                            self.print_colored("💾 Subnets data saved incrementally", Colors.GREEN)
                        else:
                            self.print_colored("⚠️ No subnets found", Colors.YELLOW, Severity.MEDIUM)
                    except Exception as e:
                        self.print_colored(f"⚠️ Failed to analyze subnets: {e}", Colors.YELLOW, Severity.MEDIUM)
                else:
                    self.print_colored("⚠️ No computers found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate computers: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping computer enumeration - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to enumerate printers
        if ldap_connected:
            try:
                self.print_colored("🖨️ Attempting to enumerate printers...", Colors.CYAN)
                printers = self.get_printers()
                if printers:
                    self.print_colored(f"✅ Retrieved {len(printers)} printers", Colors.GREEN)
                    # Save printers immediately
                    self.save_csv(printers, 'printers.csv')
                    self.print_colored("💾 Printers data saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ No printers found or insufficient permissions", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to enumerate printers: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping printer enumeration - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to retrieve password policy
        password_policy = {}
        if ldap_connected:
            try:
                self.print_colored("🔐 Retrieving password policy...", Colors.CYAN)
                password_policy = self.get_password_policy()
                if password_policy:
                    self.print_colored("✅ Password policy retrieved and analyzed", Colors.GREEN)
                    # Save password policy immediately
                    self.save_json(password_policy, 'password_policy.json')
                    self.print_colored("💾 Password policy saved incrementally", Colors.GREEN)
                else:
                    self.print_colored("⚠️ Could not retrieve password policy", Colors.YELLOW, Severity.MEDIUM)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to retrieve password policy: {e}", Colors.YELLOW, Severity.MEDIUM)
        else:
            self.print_colored("⚠️ Skipping password policy retrieval - LDAP not connected", Colors.YELLOW, Severity.MEDIUM)
        
        # Analyze user activity risks
        if users:
            try:
                self.print_colored("🔍 Analyzing user activity risks...", Colors.CYAN)
                self.analyze_user_activity_risks(users)
                self.print_colored("✅ User activity risk analysis completed", Colors.GREEN)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to analyze user activity risks: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Try to detect misconfigurations
        if users or computers:
            try:
                self.print_colored("🛑 Detecting misconfigurations...", Colors.CYAN)
                self.detect_misconfigurations(users, computers)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to detect misconfigurations: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Generate comprehensive findings and final report
        self.print_colored("📊 Generating comprehensive report...", Colors.CYAN)
        
        # Analyze subnets if computers were found
        subnets = []
        if computers:
            try:
                subnets = self.analyze_subnets(computers)
            except Exception as e:
                self.print_colored(f"⚠️ Failed to analyze subnets for final report: {e}", Colors.YELLOW, Severity.MEDIUM)
        
        # Get old logon users
        old_logon_users = self.get_users_with_old_logon(users, 180)
        
        # Get old password users
        old_password_users = self.get_users_with_old_passwords(users, 90)
        
        # Get users who never logged on
        never_logon_users = self.get_users_never_logon(users)
        
        findings_data = {
            'domain_admins': domain_admins,
            'users': users,
            'credential_candidates': credential_candidates,
            'kerberoast_candidates': kerberoast_candidates,
            'asrep_candidates': asrep_candidates,
            'gpos': gpos,
            'all_groups': all_groups,
            'computers': computers,
            'printers': printers,
            'subnets': subnets,
            'old_logon_users': old_logon_users,
            'old_password_users': old_password_users,
            'never_logon_users': never_logon_users,
            'password_policy': password_policy,
            'findings': [asdict(f) for f in self.findings]
        }
        
        # Save comprehensive findings
        self.save_json(findings_data, 'findings.json')
        self.generate_html_report(findings_data)
        self.print_colored("💾 Comprehensive findings saved", Colors.GREEN)
        
        # Generate username list for password spraying
        if users:
            usernames = [user.get('sAMAccountName', '') for user in users if user.get('sAMAccountName')]
            self.save_txt(usernames, 'usernames.txt')
            self.print_colored(f"💾 Username list saved: {len(usernames)} usernames", Colors.GREEN)
        
        # Summary of what was collected
        total_items = len(domain_admins) + len(users) + len(computers) + len(printers) + len(gpos)
        self.print_colored(f"✅ Full mode completed. Results saved to: {output_folder}", Colors.GREEN)
        self.print_colored(f"📊 Total items collected: {total_items}", Colors.CYAN)
        
        if total_items == 0:
            self.print_colored("⚠️ No data was collected. This may indicate insufficient permissions.", Colors.YELLOW, Severity.MEDIUM)
        
        return True



    def run_user_inspect_mode(self, target_user: str):
        """Run single user inspection mode"""
        self.print_colored(f"🔍 Starting user inspection for: {target_user}", Colors.BLUE)
        
        if not self.connect_ldap("user-inspect"):
            return False
        
        # Search for specific user
        user_filter = f"(&(objectClass=user)(sAMAccountName={target_user}))"
        search_base = self._get_search_base_dn()
        users = self.search_ldap(
            search_base,
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