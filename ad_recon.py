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
import hashlib
import hmac
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
    def __init__(self, dc_ip: str, domain: str, username: str = None, password: str = None, hash: str = None, skip_security_checks: bool = False):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.hash = hash
        self.skip_security_checks = skip_security_checks
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
                        # Store for later consolidated reporting
                        if not hasattr(self, 'domain_admin_passwords'):
                            self.domain_admin_passwords = []
                        self.domain_admin_passwords.append(f"{member['sAMAccountName']}: {description}")
        
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
        
        # Store adminCount=1 users for later analysis (don't create finding here)
        self.admin_count_users = admin_count_users
        
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
                                
                                # Check for password in description and collect for later reporting
                                if has_password_in_desc:
                                    self.print_colored(f"🔴 [HIGH] Password found in user description: {username}: {description}", Colors.RED, Severity.HIGH)
                                    # Store for later consolidated reporting
                                    if not hasattr(self, 'non_admin_passwords'):
                                        self.non_admin_passwords = []
                                    self.non_admin_passwords.append(f"{username}: {description}")
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
        """Enumerate computer objects with IP resolution and LAPS status"""
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
                except socket.gaierror:
                    computer['ip_address'] = "Unresolved"
                
                # Add LAPS status (this will be updated by LAPS check later)
                computer['laps_status'] = "Unknown"
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
        
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge.enabled {{
            background-color: #28a745;
            color: white;
        }}
        
        .badge.disabled {{
            background-color: #dc3545;
            color: white;
        }}
        
        .badge.admin {{
            background-color: #fd7e14;
            color: white;
        }}
        
        .badge.user {{
            background-color: #6c757d;
            color: white;
        }}
        
        .badge.laps-yes {{
            background-color: #28a745;
            color: white;
        }}
        
        .badge.laps-no {{
            background-color: #dc3545;
            color: white;
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
        
        .policy-table tr.manual {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
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
                        {self._generate_table_html(data.get('computers', []), ['name', 'ip_address', 'operatingSystem', 'description', 'laps_status'])}
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
            
            {f'''
            <div class="data-section">
                <div class="collapsible-section">
                    <h2 class="section-header" onclick="toggleSection(this)">🔒 Security Protocol Checks</h2>
                    <div class="section-content">
                        <div class="search-container">
                            <input type="text" class="search-box" id="securitySearch" placeholder="🔍 Search security findings...">
                        </div>
                        {self._generate_security_checks_html(data.get('security_results', {}))}
                    </div>
                </div>
            </div>
            ''' if data.get('security_results') else ''}

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
            setupSearch('securitySearch');
            setupSearch('lapsSearch');
            setupSearch('lapsWithSearch');
            
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
                elif col == 'laps_status':
                    # LAPS status already contains HTML badges, don't escape
                    value = str(value)
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
        
        html_parts = ['<table>', '<thead><tr>', '<th>User</th>', '<th>Description</th>', '<th>Status</th>', '<th>Domain Admin</th>', '</tr></thead><tbody>']
        
        # Get domain admin usernames for comparison
        domain_admin_usernames = set()
        try:
            domain_admins = self.get_domain_admins()
            for admin in domain_admins:
                domain_admin_usernames.add(admin.get('sAMAccountName', '').lower())
        except:
            pass
        
        for candidate in credential_candidates:
            # Parse the candidate string (format: "username: description")
            if ':' in candidate:
                parts = candidate.split(':', 1)
                username = parts[0].strip()
                description = parts[1].strip() if len(parts) > 1 else ''
            else:
                username = candidate.strip()
                description = ''
            
            # Determine if user is enabled/disabled (this is a simplified check)
            # In a real implementation, you'd need to check the userAccountControl attribute
            is_enabled = "Enabled"  # Default assumption
            is_admin = "Yes" if username.lower() in domain_admin_usernames else "No"
            
            html_parts.append(f'<tr>')
            html_parts.append(f'<td>{html.escape(username)}</td>')
            html_parts.append(f'<td>{html.escape(description)}</td>')
            html_parts.append(f'<td><span class="badge enabled">{is_enabled}</span></td>')
            html_parts.append(f'<td><span class="badge {"admin" if is_admin == "Yes" else "user"}">{is_admin}</span></td>')
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
        
        # Create consolidated findings for adminCount=1 and password in description issues
        self._create_consolidated_findings(users)

    def _create_consolidated_findings(self, users: List[Dict]):
        """Create consolidated findings for adminCount=1 and password in description issues"""
        
        # 1. Consolidated adminCount=1 finding
        admin_count_users = getattr(self, 'admin_count_users', [])
        if admin_count_users:
            admin_list = [f"• {user}" for user in admin_count_users]
            self.add_finding(Severity.HIGH, "Privileged Accounts", 
                           "Accounts with adminCount=1",
                           f"Multiple accounts have adminCount=1 attribute:\n" + "\n".join(admin_list) +
                           "\n\n**Why this is risky:** The adminCount=1 attribute indicates these accounts are protected by the AdminSDHolder process and have elevated privileges. This creates a larger attack surface for privilege escalation." +
                           "\n\n**How attackers can exploit this:** Attackers can target these accounts for privilege escalation attacks, password spraying, or lateral movement. Compromising any of these accounts provides elevated access to the domain.")
        
        # 2. Consolidated Domain Admin password in description finding
        domain_admin_passwords = getattr(self, 'domain_admin_passwords', [])
        if domain_admin_passwords:
            password_list = [f"• {entry}" for entry in domain_admin_passwords]
            self.add_finding(Severity.HIGH, "Credential Exposure", 
                           "Password in Domain Admin description",
                           f"Multiple Domain Admin accounts have passwords in their descriptions:\n" + "\n".join(password_list) +
                           "\n\n**Why this is risky:** Passwords stored in user descriptions are easily accessible to anyone with read access to Active Directory. This is a critical security risk for administrative accounts." +
                           "\n\n**How attackers can exploit this:** Attackers can extract these passwords and use them for privilege escalation, lateral movement, or direct domain compromise.")
        
        # 3. Consolidated non-admin password in description finding
        non_admin_passwords = getattr(self, 'non_admin_passwords', [])
        if non_admin_passwords:
            password_list = [f"• {entry}" for entry in non_admin_passwords]
            self.add_finding(Severity.HIGH, "Credential Exposure", 
                           "Potential credentials found in user descriptions",
                           f"Multiple non-admin users have potential credentials in their descriptions:\n" + "\n".join(password_list) +
                           "\n\n**Why this is risky:** Passwords stored in user descriptions are easily accessible to anyone with read access to Active Directory. This can lead to account compromise and potential lateral movement." +
                           "\n\n**How attackers can exploit this:** Attackers can extract these credentials and use them for password spraying, account takeover, or lateral movement within the network.")

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

    def check_llmnr_nbtns_configuration(self) -> Dict[str, Any]:
        """Check LLMNR and NBT-NS configuration"""
        self.print_colored("🔍 Checking LLMNR/NBT-NS configuration...", Colors.CYAN)
        
        results = {
            'llmnr_enabled': False,
            'nbns_enabled': False,
            'vulnerabilities': []
        }
        
        try:
            # Query for LLMNR and NBT-NS settings in Group Policy
            gpo_filter = "(objectClass=groupPolicyContainer)"
            gpos = self.search_ldap(self._get_search_base_dn(), gpo_filter, ['name', 'displayName'])
            
            for gpo in gpos:
                gpo_name = gpo.get('name', 'Unknown')
                # Check for LLMNR/NBT-NS related settings in GPO
                # This would require parsing GPO files, but for now we'll check registry settings
                pass
            
            # Add finding with actual status information
            self.add_finding(Severity.MEDIUM, "Network Protocols", 
                           "LLMNR/NBT-NS Configuration Check",
                           "LLMNR and NBT-NS protocols should be disabled to prevent NBT-NS/LLMNR poisoning attacks. " +
                           "These protocols allow attackers to intercept name resolution requests and redirect traffic." +
                           "\n\n**Current Status:** Manual verification required - check Group Policy settings for:" +
                           "\n• 'Turn off multicast name resolution' (LLMNR)" +
                           "\n• 'Turn off NetBIOS over TCP/IP' (NBT-NS)" +
                           "\n\n**Why manual check needed:** Script can only analyze LDAP configuration, not active network protocols.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking LLMNR/NBT-NS: {e}", Colors.YELLOW)
        
        return results

    def check_smb_configuration(self) -> Dict[str, Any]:
        """Check SMB version and security configuration"""
        self.print_colored("🔍 Checking SMB configuration...", Colors.CYAN)
        
        results = {
            'smbv1_enabled': False,
            'smb_signing_required': False,
            'anonymous_access': False,
            'vulnerabilities': []
        }
        
        try:
            # Query computers for SMB configuration
            computer_filter = "(objectClass=computer)"
            computers = self.search_ldap(self._get_search_base_dn(), computer_filter, ['name', 'operatingSystem'])
            
            # Check for SMBv1 usage indicators
            smbv1_indicators = []
            for computer in computers:
                os = computer.get('operatingSystem', '')
                if 'Windows 7' in os or 'Windows Server 2008' in os:
                    smbv1_indicators.append(computer.get('name', 'Unknown'))
            
            if smbv1_indicators:
                results['smbv1_enabled'] = True
                results['vulnerabilities'].append(f"SMBv1 likely enabled on {len(smbv1_indicators)} systems")
                
                self.add_finding(Severity.HIGH, "SMB Security", 
                               "SMBv1 Protocol Detected",
                               f"SMBv1 protocol is likely enabled on {len(smbv1_indicators)} systems: {', '.join(smbv1_indicators[:5])}" +
                               "\n\n**Why this is risky:** SMBv1 is deprecated and vulnerable to various attacks including EternalBlue." +
                               "\n\n**How attackers can exploit this:** Attackers can use tools like EternalBlue to exploit SMBv1 vulnerabilities for remote code execution.")
            
            # Check for SMB signing requirements
            self.add_finding(Severity.MEDIUM, "SMB Security", 
                           "SMB Signing Configuration",
                           "SMB signing should be required to prevent man-in-the-middle attacks. " +
                           "Check Group Policy settings for 'Microsoft network server: Digitally sign communications (always)'" +
                           "\n\n**Current Status:** Manual verification required - check Group Policy settings for SMB signing requirements." +
                           "\n\n**Why manual check needed:** Script can only detect SMBv1 usage from OS versions, not actual protocol configuration.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking SMB configuration: {e}", Colors.YELLOW)
        
        return results

    def check_ntlm_configuration(self) -> Dict[str, Any]:
        """Check NTLM authentication configuration"""
        self.print_colored("🔍 Checking NTLM configuration...", Colors.CYAN)
        
        results = {
            'ntlmv1_enabled': False,
            'ntlmv1_fallback': False,
            'ntlmv2_required': False,
            'vulnerabilities': []
        }
        
        try:
            # Check domain controller settings for NTLM configuration
            dc_filter = "(objectClass=computer)"
            dcs = self.search_ldap(self._get_search_base_dn(), dc_filter, ['name', 'operatingSystem'])
            
            # Add findings about NTLM security
            self.add_finding(Severity.MEDIUM, "Authentication", 
                           "NTLM Authentication Security",
                           "NTLMv1 should be disabled and NTLMv2 should be required. " +
                           "NTLMv1 uses weak encryption and is vulnerable to various attacks." +
                           "\n\n**Current Status:** Manual verification required - check Group Policy settings for:" +
                           "\n• 'Network security: LAN Manager authentication level'" +
                           "\n• 'Network security: Minimum session security for NTLM SSP'" +
                           "\n\n**Recommendations:**" +
                           "\n• Disable NTLMv1" +
                           "\n• Require NTLMv2" +
                           "\n• Consider disabling NTLM entirely in favor of Kerberos")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking NTLM configuration: {e}", Colors.YELLOW)
        
        return results

    def check_ldap_security(self) -> Dict[str, Any]:
        """Check LDAP security configuration"""
        self.print_colored("🔍 Checking LDAP security configuration...", Colors.CYAN)
        
        results = {
            'ldaps_enabled': False,
            'ldap_signing_required': False,
            'channel_binding_required': False,
            'simple_bind_allowed': True,
            'vulnerabilities': []
        }
        
        try:
            # Check if we're using LDAPS
            if self.connection and hasattr(self.connection, 'server'):
                if self.connection.server.ssl:
                    results['ldaps_enabled'] = True
                else:
                    self.add_finding(Severity.HIGH, "LDAP Security", 
                                   "LDAPS Not Used",
                                   "LDAP is not using SSL/TLS encryption. " +
                                   "This means authentication credentials and data are transmitted in plain text." +
                                   "\n\n**Risk:** Credentials and sensitive data can be intercepted by attackers.")
            
            # Check for LDAP signing requirements
            self.add_finding(Severity.MEDIUM, "LDAP Security", 
                           "LDAP Signing and Channel Binding",
                           "LDAP signing should be required and channel binding should be enabled to prevent LDAP relay attacks." +
                           "\n\n**Current Status:** Manual verification required - check Group Policy settings for:" +
                           "\n• 'Domain controller: LDAP server signing requirements'" +
                           "\n• 'Domain controller: LDAP server channel binding token requirements'" +
                           "\n\n**Recommendations:**" +
                           "\n• Enable LDAP signing" +
                           "\n• Enable LDAP channel binding" +
                           "\n• Disable LDAP simple bind")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking LDAP security: {e}", Colors.YELLOW)
        
        return results

    def extract_cpasswords(self) -> List[Dict[str, Any]]:
        """Extract and decrypt cPasswords from Group Policy Objects"""
        self.print_colored("🔍 Extracting cPasswords from GPOs...", Colors.CYAN)
        
        cpasswords = []
        total_files_checked = 0
        
        try:
            # Get domain SID for key derivation
            domain_sid = self._get_domain_sid()
            if not domain_sid:
                self.print_colored("⚠️ Could not retrieve domain SID for cPassword decryption", Colors.YELLOW)
                return self._extract_cpasswords_manual_guidance()
            
            self.print_colored(f"🔑 Using Domain SID for decryption: {domain_sid}", Colors.CYAN)
            
            # Test decryption with a sample if we find any cPasswords
            test_decryption_worked = False
            
            # Get all GPOs
            gpo_filter = "(objectClass=groupPolicyContainer)"
            gpos = self.search_ldap(self._get_search_base_dn(), gpo_filter, ['name', 'displayName', 'whenCreated'])
            
            self.print_colored(f"🔍 Found {len(gpos)} GPOs to scan for cPasswords", Colors.CYAN)
            
            for gpo in gpos:
                gpo_name = gpo.get('name', 'Unknown')
                gpo_display = gpo.get('displayName', gpo_name)
                
                # Try to extract cPasswords from this GPO
                gpo_cpasswords = self._extract_gpo_cpasswords(gpo_name, gpo_display, domain_sid)
                cpasswords.extend(gpo_cpasswords)
                
                # Count files checked
                for cpwd in gpo_cpasswords:
                    if cpwd.get('checked_files'):
                        total_files_checked += len(cpwd['checked_files'])
            
            # Also try to scan the entire SYSVOL for any XML files with cPasswords
            self.print_colored("🔍 Scanning entire SYSVOL for cPasswords...", Colors.CYAN)
            sysvol_cpasswords = self._scan_entire_sysvol_for_cpasswords(domain_sid)
            cpasswords.extend(sysvol_cpasswords)
            
            # Also search for cPasswords in registry files and other locations
            self.print_colored("🔍 Searching for cPasswords in registry and other files...", Colors.CYAN)
            registry_cpasswords = self._search_registry_for_cpasswords(domain_sid)
            cpasswords.extend(registry_cpasswords)
            
            if cpasswords:
                decrypted_count = len([cpwd for cpwd in cpasswords if cpwd.get('status') == 'decrypted' and cpwd.get('password') != 'Unknown'])
                failed_count = len(cpasswords) - decrypted_count
                
                self.print_colored(f"✅ Found {len(cpasswords)} cPassword entries, {decrypted_count} successfully decrypted, {failed_count} failed", Colors.GREEN)
                
                if failed_count > 0:
                    self.print_colored(f"⚠️ {failed_count} cPasswords failed to decrypt. Check domain SID and encryption method.", Colors.YELLOW)
                    
                    # Show sample cPassword values for debugging
                    sample_cpasswords = [cpwd for cpwd in cpasswords if cpwd.get('encrypted_value')][:3]
                    if sample_cpasswords:
                        self.print_colored("🔍 Sample cPassword values found:", Colors.CYAN)
                        for i, cpwd in enumerate(sample_cpasswords, 1):
                            self.print_colored(f"  {i}. {cpwd.get('encrypted_value', 'Unknown')}", Colors.CYAN)
                
                decrypted_credentials = [f"• {cpwd['gpo_display']}: {cpwd['username']} / {cpwd['password']}" for cpwd in cpasswords if cpwd.get('status') == 'decrypted' and cpwd.get('password') != 'Unknown']
                
                self.add_finding(Severity.HIGH, "Credential Exposure", 
                               f"GPO cPasswords Found",
                               f"Successfully extracted {len(cpasswords)} cPassword(s) from GPOs." +
                               f"\n\n**Decrypted Credentials:** {decrypted_count}" +
                               f"\n**Failed Decryptions:** {failed_count}" +
                               "\n" + "\n".join(decrypted_credentials[:5]) +
                               "\n\n**Risk:** Stored credentials in GPOs can be used for privilege escalation and lateral movement.")
            else:
                self.add_finding(Severity.INFO, "Credential Exposure", 
                               "No cPasswords Found",
                               "No cPasswords were found in Group Policy Objects. This is good security practice.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error extracting cPasswords: {e}", Colors.YELLOW)
            return self._extract_cpasswords_manual_guidance()
        
        return cpasswords

    def _get_domain_sid(self) -> str:
        """Get the domain SID for cPassword decryption"""
        try:
            # Query for domain object to get SID
            domain_filter = "(objectClass=domain)"
            domain_info = self.search_ldap(self._get_search_base_dn(), domain_filter, ['objectSid'])
            
            if domain_info and domain_info[0].get('objectSid'):
                return domain_info[0]['objectSid']
            
            return None
        except Exception as e:
            self.print_colored(f"⚠️ Error getting domain SID: {e}", Colors.YELLOW)
            return None

    def _extract_gpo_cpasswords(self, gpo_name: str, gpo_display: str, domain_sid: str) -> List[Dict[str, Any]]:
        """Extract cPasswords from a specific GPO by searching ALL files recursively"""
        cpasswords = []
        checked_files = []
        
        try:
            # Base GPO path
            gpo_base_path = f"\\\\{self.dc_ip}\\SYSVOL\\{self.domain}\\Policies\\{gpo_name}"
            
            # Search for ALL XML files in the GPO recursively
            xml_files = self._find_xml_files_in_gpo(gpo_base_path)
            
            for xml_file_path in xml_files:
                checked_files.append(xml_file_path)
                
                # Try to read the XML file
                xml_content = self._read_sysvol_file(xml_file_path)
                if xml_content:
                    # Parse XML and extract cPasswords
                    extracted_passwords = self._parse_groups_xml(xml_content, domain_sid)
                    for password_info in extracted_passwords:
                        cpasswords.append({
                            'gpo_name': gpo_name,
                            'gpo_display': gpo_display,
                            'username': password_info.get('username', 'Unknown'),
                            'password': password_info.get('password', 'Unknown'),
                            'status': 'decrypted',
                            'location': xml_file_path
                        })
            
            # If no cPasswords found, add to manual check list with all checked files
            if not cpasswords:
                cpasswords.append({
                    'gpo_name': gpo_name,
                    'gpo_display': gpo_display,
                    'username': 'Unknown',
                    'password': 'Unknown',
                    'status': 'requires_manual_check',
                    'location': gpo_base_path,
                    'checked_files': checked_files,
                    'files_checked_count': len(checked_files)
                })
            
        except Exception as e:
            self.print_colored(f"⚠️ Error extracting from GPO {gpo_display}: {e}", Colors.YELLOW)
            # Add to manual check list on error
            cpasswords.append({
                'gpo_name': gpo_name,
                'gpo_display': gpo_display,
                'username': 'Unknown',
                'password': 'Unknown',
                'status': 'requires_manual_check',
                'location': f"\\\\{self.dc_ip}\\SYSVOL\\{self.domain}\\Policies\\{gpo_name}\\",
                'error': str(e),
                'checked_files': checked_files
            })
        
        return cpasswords

    def _scan_entire_sysvol_for_cpasswords(self, domain_sid: str) -> List[Dict[str, Any]]:
        """Scan the entire SYSVOL for any XML files containing cPasswords"""
        cpasswords = []
        
        try:
            # Base SYSVOL path
            sysvol_base = f"\\\\{self.dc_ip}\\SYSVOL\\{self.domain}"
            
            self.print_colored(f"🔍 Scanning entire SYSVOL: {sysvol_base}", Colors.CYAN)
            
            # Walk through all directories in SYSVOL
            for root, dirs, files in os.walk(sysvol_base):
                for file in files:
                    if file.lower().endswith('.xml'):
                        file_path = os.path.join(root, file)
                        
                        try:
                            # Try to read the XML file
                            xml_content = self._read_sysvol_file(file_path)
                            if xml_content:
                                # Parse XML and extract cPasswords
                                extracted_passwords = self._parse_groups_xml(xml_content, domain_sid)
                                for password_info in extracted_passwords:
                                    # Try to determine GPO name from path
                                    gpo_name = "Unknown"
                                    if "Policies" in file_path:
                                        path_parts = file_path.split("\\")
                                        for i, part in enumerate(path_parts):
                                            if part == "Policies" and i + 1 < len(path_parts):
                                                gpo_name = path_parts[i + 1]
                                                break
                                    
                                    cpasswords.append({
                                        'gpo_name': gpo_name,
                                        'gpo_display': f"SYSVOL Scan - {gpo_name}",
                                        'username': password_info.get('username', 'Unknown'),
                                        'password': password_info.get('password', 'Unknown'),
                                        'status': 'decrypted',
                                        'location': file_path
                                    })
                        except Exception as e:
                            # Continue with next file
                            continue
                            
        except Exception as e:
            self.print_colored(f"⚠️ Error scanning SYSVOL: {e}", Colors.YELLOW)
        
        return cpasswords

    def _search_registry_for_cpasswords(self, domain_sid: str) -> List[Dict[str, Any]]:
        """Search for cPasswords in registry files and other locations"""
        cpasswords = []
        
        try:
            # Search for registry files that might contain cPasswords
            registry_paths = [
                f"\\\\{self.dc_ip}\\SYSVOL\\{self.domain}\\Policies\\*\\Machine\\Registry.pol",
                f"\\\\{self.dc_ip}\\SYSVOL\\{self.domain}\\Policies\\*\\User\\Registry.pol"
            ]
            
            import glob
            for pattern in registry_paths:
                try:
                    registry_files = glob.glob(pattern)
                    for registry_file in registry_files:
                        try:
                            # Try to read registry file content
                            content = self._read_sysvol_file(registry_file)
                            if content:
                                # Look for cPassword patterns in registry content
                                import re
                                cpassword_matches = re.findall(r'cpassword["\s]*[:=]["\s]*([^"\s]+)', content, re.IGNORECASE)
                                
                                for match in cpassword_matches:
                                    decrypted_password = self._decrypt_cpassword(match, domain_sid)
                                    if decrypted_password:
                                        # Try to extract GPO name from path
                                        gpo_name = "Unknown"
                                        if "Policies" in registry_file:
                                            path_parts = registry_file.split("\\")
                                            for i, part in enumerate(path_parts):
                                                if part == "Policies" and i + 1 < len(path_parts):
                                                    gpo_name = path_parts[i + 1]
                                                    break
                                        
                                        cpasswords.append({
                                            'gpo_name': gpo_name,
                                            'gpo_display': f"Registry - {gpo_name}",
                                            'username': 'Registry Entry',
                                            'password': decrypted_password,
                                            'status': 'decrypted',
                                            'location': registry_file
                                        })
                        except Exception as e:
                            continue
                except Exception as e:
                    continue
                    
        except Exception as e:
            self.print_colored(f"⚠️ Error searching registry: {e}", Colors.YELLOW)
        
        return cpasswords

    def _read_sysvol_file(self, file_path: str) -> str:
        """Read a file from SYSVOL share"""
        try:
            # Try to read the file using UNC path
            # This requires appropriate permissions and network access
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            # File doesn't exist or no access
            return None
        except PermissionError:
            # No permission to access the file
            return None
        except Exception as e:
            # Other errors (network, etc.)
            return None
    
    def _find_xml_files_in_gpo(self, gpo_base_path: str) -> List[str]:
        """Find ALL XML files in a GPO recursively"""
        xml_files = []
        
        try:
            # Use os.walk to recursively search for XML files
            for root, dirs, files in os.walk(gpo_base_path):
                for file in files:
                    if file.lower().endswith('.xml'):
                        full_path = os.path.join(root, file)
                        xml_files.append(full_path)
                        
        except PermissionError:
            # If we can't access the directory, try common paths
            common_paths = [
                os.path.join(gpo_base_path, "Machine", "Preferences", "Groups", "Groups.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "Groups", "Groups.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "Services", "Services.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "Services", "Services.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "ScheduledTasks", "ScheduledTasks.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "DataSources", "DataSources.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "DataSources", "DataSources.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "Drives", "Drives.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "Drives", "Drives.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "IniFiles", "IniFiles.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "IniFiles", "IniFiles.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "Registry", "Registry.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "Registry", "Registry.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "Shortcuts", "Shortcuts.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "Shortcuts", "Shortcuts.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "StartMenu", "StartMenu.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "StartMenu", "StartMenu.xml"),
                os.path.join(gpo_base_path, "Machine", "Preferences", "WindowsSettings", "WindowsSettings.xml"),
                os.path.join(gpo_base_path, "User", "Preferences", "WindowsSettings", "WindowsSettings.xml")
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    xml_files.append(path)
                    
        except Exception as e:
            self.print_colored(f"⚠️ Error searching GPO {gpo_base_path}: {e}", Colors.YELLOW)
        
        return xml_files

    def _parse_groups_xml(self, xml_content: str, domain_sid: str) -> List[Dict[str, str]]:
        """Parse XML files and extract cPasswords"""
        passwords = []
        
        try:
            # Parse XML content
            root = ET.fromstring(xml_content)
            
            # Look for Groups element (Groups.xml)
            for groups in root.findall('.//Groups'):
                for group in groups.findall('.//Group'):
                    # Look for cPassword attribute
                    cpassword = group.get('cpassword')
                    if cpassword:
                        # Decrypt the password
                        decrypted_password = self._decrypt_cpassword(cpassword, domain_sid)
                        if decrypted_password:
                            # Get username from the group
                            username = group.get('userName', 'Unknown')
                            passwords.append({
                                'username': username,
                                'password': decrypted_password
                            })
            
            # Look for Services element (Services.xml)
            for services in root.findall('.//Services'):
                for service in services.findall('.//Service'):
                    # Look for cPassword attribute
                    cpassword = service.get('cpassword')
                    if cpassword:
                        # Decrypt the password
                        decrypted_password = self._decrypt_cpassword(cpassword, domain_sid)
                        if decrypted_password:
                            # Get service name
                            service_name = service.get('serviceName', 'Unknown')
                            passwords.append({
                                'username': service_name,
                                'password': decrypted_password
                            })
            
            # Look for any element with cpassword attribute (comprehensive search)
            for element in root.findall('.//*[@cpassword]'):
                cpassword = element.get('cpassword')
                if cpassword:
                    # Decrypt the password
                    decrypted_password = self._decrypt_cpassword(cpassword, domain_sid)
                    if decrypted_password:
                        # Try to get username or name from various attributes
                        username = (element.get('userName') or 
                                  element.get('name') or 
                                  element.get('id') or 
                                  element.get('accountName') or
                                  element.get('serviceName') or
                                  element.get('taskName') or
                                  element.get('dataSourceName') or
                                  element.get('driveLetter') or
                                  'Unknown')
                        passwords.append({
                            'username': username,
                            'password': decrypted_password,
                            'encrypted_value': cpassword[:20] + '...' if len(cpassword) > 20 else cpassword
                        })
                    else:
                        # Store failed decryption attempt
                        passwords.append({
                            'username': 'Decryption Failed',
                            'password': 'Unknown',
                            'encrypted_value': cpassword[:20] + '...' if len(cpassword) > 20 else cpassword,
                            'decryption_error': 'Failed to decrypt cPassword'
                        })
            
            # Also search for cpassword in text content (some GPOs store it differently)
            for element in root.findall('.//*'):
                text_content = element.text
                if text_content and 'cpassword' in text_content.lower():
                    # Try to extract cpassword from text content
                    import re
                    cpassword_match = re.search(r'cpassword="([^"]+)"', text_content, re.IGNORECASE)
                    if cpassword_match:
                        cpassword = cpassword_match.group(1)
                        decrypted_password = self._decrypt_cpassword(cpassword, domain_sid)
                        if decrypted_password:
                            # Try to extract username from the same text
                            username_match = re.search(r'username="([^"]+)"', text_content, re.IGNORECASE)
                            username = username_match.group(1) if username_match else 'Unknown'
                            passwords.append({
                                'username': username,
                                'password': decrypted_password
                            })
            
        except ET.ParseError as e:
            # XML parsing error
            self.print_colored(f"⚠️ XML parsing error: {e}", Colors.YELLOW)
        except Exception as e:
            # Other errors
            self.print_colored(f"⚠️ Error parsing XML: {e}", Colors.YELLOW)
        
        return passwords

    def _decrypt_cpassword(self, encrypted_password: str, domain_sid: str) -> str:
        """Decrypt a cPassword using the domain SID"""
        try:
            # Microsoft cPassword decryption algorithm
            # Based on Microsoft's implementation for GPO stored passwords
            
            if not encrypted_password or not domain_sid:
                return None
            
            # Store error information for debugging
            error_info = []
            
            # Convert domain SID to bytes
            if domain_sid.startswith('S-'):
                sid_parts = domain_sid.split('-')
                if len(sid_parts) >= 8:
                    # Extract the domain SID (first 8 parts)
                    domain_sid_bytes = b''
                    for i in range(1, 8):  # Skip 'S' and take next 7 parts
                        domain_sid_bytes += int(sid_parts[i]).to_bytes(4, 'little')
                    
                    # Microsoft's key derivation
                    # Use the domain SID as salt for PBKDF2
                    salt = domain_sid_bytes
                    
                    # Microsoft uses a specific password for key derivation
                    # This is the hardcoded password used by Microsoft
                    ms_password = b'password'
                    
                    # Derive key using PBKDF2
                    key = hashlib.pbkdf2_hmac('sha1', ms_password, salt, 1000, 32)
                    
                    # Decode the base64 encrypted password
                    try:
                        encrypted_bytes = base64.b64decode(encrypted_password)
                    except:
                        # If base64 decode fails, try without padding
                        try:
                            encrypted_bytes = base64.b64decode(encrypted_password + '==')
                        except:
                            # If still fails, try with different padding
                            try:
                                encrypted_bytes = base64.b64decode(encrypted_password + '=')
                            except:
                                error_info.append(f"Base64 decode failed: {encrypted_password[:20]}...")
                                self.print_colored(f"⚠️ Failed to decode base64: {encrypted_password[:20]}...", Colors.YELLOW)
                                return None
                    
                    # Extract IV (first 16 bytes) and ciphertext
                    if len(encrypted_bytes) >= 16:
                        iv = encrypted_bytes[:16]
                        ciphertext = encrypted_bytes[16:]
                        
                        # Decrypt using AES-256-CBC
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        
                        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
                        
                        # Remove padding
                        if len(decrypted_bytes) > 0:
                            padding_length = decrypted_bytes[-1]
                            if padding_length <= 16 and padding_length > 0: # Ensure padding is valid
                                decrypted_bytes = decrypted_bytes[:-padding_length]
                        
                        # Convert to string - try multiple encodings
                        for encoding in ['utf-16le', 'utf-16', 'utf-8']:
                            try:
                                decrypted_password = decrypted_bytes.decode(encoding)
                                # Validate the result - should be printable
                                if decrypted_password and decrypted_password.isprintable():
                                    return decrypted_password
                            except:
                                continue
                        
                        # If all encodings fail, return as hex
                        return decrypted_bytes.hex()
                    else:
                        error_info.append("Insufficient encrypted data length")
                        return None
                else:
                    error_info.append("Invalid domain SID format")
                    return None
            else:
                error_info.append("Invalid domain SID format")
                return None
            
        except Exception as e:
            error_info.append(f"Decryption exception: {str(e)}")
            self.print_colored(f"⚠️ Error decrypting cPassword: {e}", Colors.YELLOW)
            return None

    def _extract_cpasswords_manual_guidance(self) -> List[Dict[str, Any]]:
        """Fallback method that provides manual guidance when automatic extraction fails"""
        cpasswords = []
        
        try:
            # Get all GPOs for manual guidance
            gpo_filter = "(objectClass=groupPolicyContainer)"
            gpos = self.search_ldap(self._get_search_base_dn(), gpo_filter, ['name', 'displayName', 'whenCreated'])
            
            for gpo in gpos:
                gpo_name = gpo.get('name', 'Unknown')
                gpo_display = gpo.get('displayName', gpo_name)
                
                self.add_finding(Severity.HIGH, "Credential Exposure", 
                               f"GPO cPassword Check - {gpo_display}",
                               f"Group Policy Object '{gpo_display}' should be checked for stored credentials (cPasswords)." +
                               "\n\n**How to extract cPasswords:**" +
                               "\n1. Access SYSVOL share on domain controller" +
                               "\n2. Navigate to GPO folder" +
                               "\n3. Look for Groups.xml file" +
                               "\n4. Extract and decrypt cPassword values" +
                               "\n\n**Decryption method:**" +
                               "\n• Use domain's AES key (derived from domain SID)" +
                               "\n• Decrypt using AES-256-CBC" +
                               "\n• Key derivation: PBKDF2 with domain SID as salt")
                
                cpasswords.append({
                    'gpo_name': gpo_name,
                    'gpo_display': gpo_display,
                    'status': 'requires_manual_check',
                    'location': f'\\\\{self.dc_ip}\\SYSVOL\\{self.domain}\\Policies\\{gpo_name}\\Machine\\Preferences\\Groups\\Groups.xml'
                })
            
        except Exception as e:
            self.print_colored(f"⚠️ Error in manual guidance: {e}", Colors.YELLOW)
        
        return cpasswords

    def check_ad_cs_vulnerabilities(self) -> Dict[str, Any]:
        """Check Active Directory Certificate Services for common vulnerabilities"""
        self.print_colored("🔍 Checking AD CS vulnerabilities...", Colors.CYAN)
        
        results = {
            'templates_found': 0,
            'vulnerable_templates': [],
            'esc1_vulnerable': False,
            'esc2_vulnerable': False,
            'esc3_vulnerable': False,
            'esc4_vulnerable': False,
            'esc5_vulnerable': False,
            'esc6_vulnerable': False,
            'esc7_vulnerable': False,
            'esc8_vulnerable': False
        }
        
        try:
            # Query for AD CS templates
            template_filter = "(objectClass=pKICertificateTemplate)"
            templates = self.search_ldap(self._get_search_base_dn(), template_filter, [
                'name', 'displayName', 'pKIExtendedKeyUsage', 'pKIEnrollmentFlag', 
                'pKICriticalExtensions', 'pKIDefaultKeySpec', 'pKIKeyUsage'
            ])
            
            results['templates_found'] = len(templates)
            
            for template in templates:
                template_name = template.get('name', 'Unknown')
                display_name = template.get('displayName', template_name)
                
                # Check for ESC1 vulnerability (misconfigured certificate template)
                if self._check_esc1_vulnerability(template):
                    results['esc1_vulnerable'] = True
                    results['vulnerable_templates'].append({
                        'name': template_name,
                        'display_name': display_name,
                        'vulnerability': 'ESC1',
                        'description': 'Template allows enrollment by any authenticated user and has client authentication EKU'
                    })
                
                # Check for ESC2 vulnerability (no EKU specified)
                if self._check_esc2_vulnerability(template):
                    results['esc2_vulnerable'] = True
                    results['vulnerable_templates'].append({
                        'name': template_name,
                        'display_name': display_name,
                        'vulnerability': 'ESC2',
                        'description': 'Template has no EKU specified, allowing any purpose'
                    })
                
                # Add more ESC vulnerability checks here...
            
            if results['vulnerable_templates']:
                self.add_finding(Severity.HIGH, "AD CS Security", 
                               "Vulnerable Certificate Templates Detected",
                               f"Found {len(results['vulnerable_templates'])} vulnerable certificate templates: " +
                               "\n".join([f"• {t['display_name']} ({t['vulnerability']}): {t['description']}" for t in results['vulnerable_templates']]) +
                               "\n\n**Why this is risky:** Vulnerable certificate templates can allow privilege escalation and domain compromise." +
                               "\n\n**How attackers can exploit this:** Attackers can enroll in vulnerable templates to obtain certificates for authentication and privilege escalation.")
            else:
                self.add_finding(Severity.INFO, "AD CS Security", 
                               "Certificate Templates Appear Secure",
                               f"Checked {results['templates_found']} certificate templates. No obvious vulnerabilities detected.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking AD CS vulnerabilities: {e}", Colors.YELLOW)
        
        return results

    def _check_esc1_vulnerability(self, template: Dict) -> bool:
        """Check if template is vulnerable to ESC1"""
        try:
            # ESC1: Template allows enrollment by any authenticated user and has client authentication EKU
            enrollment_flags = template.get('pKIEnrollmentFlag', [])
            extended_key_usage = template.get('pKIExtendedKeyUsage', [])
            
            # Check if template allows enrollment by any authenticated user
            if enrollment_flags and any('CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT' in str(flag) for flag in enrollment_flags):
                # Check if template has client authentication EKU
                if extended_key_usage and any('Client Authentication' in str(eku) for eku in extended_key_usage):
                    return True
            
            return False
        except:
            return False

    def _check_esc2_vulnerability(self, template: Dict) -> bool:
        """Check if template is vulnerable to ESC2"""
        try:
            # ESC2: Template has no EKU specified
            extended_key_usage = template.get('pKIExtendedKeyUsage', [])
            return len(extended_key_usage) == 0
        except:
            return False

    def check_dns_security(self) -> Dict[str, Any]:
        """Check DNS security configuration"""
        self.print_colored("🔍 Checking DNS security configuration...", Colors.CYAN)
        
        results = {
            'zone_transfers_allowed': False,
            'recursion_enabled': False,
            'dnssec_enabled': False,
            'vulnerabilities': []
        }
        
        try:
            # Check for DNS zone transfer vulnerabilities
            self.add_finding(Severity.MEDIUM, "DNS Security", 
                           "DNS Zone Transfer Security",
                           "DNS zone transfers should be restricted to authorized servers only. " +
                           "Open zone transfers can reveal internal network information to attackers.")
            
            # Check for DNS recursion
            self.add_finding(Severity.MEDIUM, "DNS Security", 
                           "DNS Recursion Configuration",
                           "DNS recursion should be disabled on external-facing DNS servers to prevent DNS amplification attacks.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking DNS security: {e}", Colors.YELLOW)
        
        return results

    def check_kerberos_security(self) -> Dict[str, Any]:
        """Check Kerberos security configuration"""
        self.print_colored("🔍 Checking Kerberos security configuration...", Colors.CYAN)
        
        results = {
            'unconstrained_delegation': [],
            'constrained_delegation': [],
            'resource_based_delegation': [],
            'preauth_disabled': [],
            'vulnerabilities': []
        }
        
        try:
            # Check for unconstrained delegation
            delegation_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            delegation_accounts = self.search_ldap(self._get_search_base_dn(), delegation_filter, ['sAMAccountName', 'userPrincipalName'])
            
            if delegation_accounts:
                results['unconstrained_delegation'] = [acc.get('sAMAccountName') for acc in delegation_accounts]
                
                self.add_finding(Severity.HIGH, "Kerberos Security", 
                               "Unconstrained Delegation Detected",
                               f"Found {len(delegation_accounts)} accounts with unconstrained delegation: " +
                               ", ".join(results['unconstrained_delegation'][:5]) +
                               "\n\n**Why this is risky:** Unconstrained delegation allows accounts to impersonate any user to any service." +
                               "\n\n**How attackers can exploit this:** Attackers can use unconstrained delegation to escalate privileges and access sensitive services.")
            
            # Check for accounts with pre-authentication disabled
            preauth_filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            preauth_accounts = self.search_ldap(self._get_search_base_dn(), preauth_filter, ['sAMAccountName', 'userPrincipalName'])
            
            if preauth_accounts:
                results['preauth_disabled'] = [acc.get('sAMAccountName') for acc in preauth_accounts]
                
                self.add_finding(Severity.HIGH, "Kerberos Security", 
                               "Pre-authentication Disabled",
                               f"Found {len(preauth_accounts)} accounts with Kerberos pre-authentication disabled: " +
                               ", ".join(results['preauth_disabled'][:5]) +
                               "\n\n**Why this is risky:** Disabled pre-authentication makes accounts vulnerable to AS-REP roasting attacks." +
                               "\n\n**How attackers can exploit this:** Attackers can request TGTs without providing a password and attempt to crack them offline.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking Kerberos security: {e}", Colors.YELLOW)
        
        return results

    def check_account_security(self) -> Dict[str, Any]:
        """Check account security policies"""
        self.print_colored("🔍 Checking account security policies...", Colors.CYAN)
        
        results = {
            'password_complexity': False,
            'account_lockout': False,
            'password_history': False,
            'account_expiration': False,
            'vulnerabilities': []
        }
        
        try:
            # Get password policy
            policy = self.get_password_policy()
            
            if policy:
                # Check password complexity
                if policy.get('minPasswordLength', 0) < 8:
                    results['vulnerabilities'].append("Weak password length requirement")
                
                # Check account lockout
                if policy.get('lockoutThreshold', 0) == 0:
                    results['vulnerabilities'].append("No account lockout policy")
                
                # Check password history
                if policy.get('passwordHistoryLength', 0) < 5:
                    results['vulnerabilities'].append("Weak password history requirement")
            
            if results['vulnerabilities']:
                self.add_finding(Severity.MEDIUM, "Account Security", 
                               "Weak Account Security Policies",
                               "Account security policies have weaknesses:\n" + "\n".join([f"• {vuln}" for vuln in results['vulnerabilities']]) +
                               "\n\n**Recommendations:**" +
                               "\n• Require minimum 8-character passwords" +
                               "\n• Enable account lockout after failed attempts" +
                               "\n• Require password history of at least 5 passwords")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking account security: {e}", Colors.YELLOW)
        
        return results

    def check_network_security(self) -> Dict[str, Any]:
        """Check network security configuration"""
        self.print_colored("🔍 Checking network security configuration...", Colors.CYAN)
        
        results = {
            'ipv6_enabled': False,
            'weak_encryption': False,
            'insecure_protocols': [],
            'vulnerabilities': []
        }
        
        try:
            # Check for IPv6 vulnerabilities
            self.add_finding(Severity.MEDIUM, "Network Security", 
                           "IPv6 Security Considerations",
                           "IPv6 should be properly configured and secured. " +
                           "Attackers can use IPv6 to bypass network controls and perform various attacks." +
                           "\n\n**Recommendations:**" +
                           "\n• Disable IPv6 if not needed" +
                           "\n• Configure IPv6 security policies" +
                           "\n• Monitor IPv6 traffic")
            
            # Check for weak encryption algorithms
            self.add_finding(Severity.MEDIUM, "Network Security", 
                           "Encryption Algorithm Security",
                           "Ensure strong encryption algorithms are used for authentication and data protection." +
                           "\n\n**Recommendations:**" +
                           "\n• Use AES-256 for encryption" +
                           "\n• Disable RC4 and DES" +
                           "\n• Require strong cipher suites")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking network security: {e}", Colors.YELLOW)
        
        return results

    def check_laps_configuration(self) -> Dict[str, Any]:
        """Check if Local Administrator Password Solution (LAPS) is configured"""
        self.print_colored("🔍 Checking LAPS configuration...", Colors.CYAN)
        
        results = {
            'laps_installed': False,
            'laps_enabled': False,
            'computers_with_laps': 0,
            'computers_without_laps': 0,
            'computers_without_laps_list': [],
            'computers_with_laps_list': [],
            'vulnerabilities': []
        }
        
        try:
            # Check for LAPS attributes on computers
            computer_filter = "(objectClass=computer)"
            computers = self.search_ldap(self._get_search_base_dn(), computer_filter, [
                'name', 'ms-Mcs-AdmPwdExpirationTime', 'ms-Mcs-AdmPwd'
            ])
            
            laps_computers = []
            non_laps_computers = []
            
            for computer in computers:
                computer_name = computer.get('name', 'Unknown')
                laps_expiration = computer.get('ms-Mcs-AdmPwdExpirationTime')
                
                if laps_expiration:
                    laps_computers.append(computer_name)
                else:
                    non_laps_computers.append(computer_name)
            
            results['computers_with_laps'] = len(laps_computers)
            results['computers_without_laps'] = len(non_laps_computers)
            results['computers_without_laps_list'] = non_laps_computers
            results['computers_with_laps_list'] = laps_computers
            
            if laps_computers:
                results['laps_installed'] = True
                results['laps_enabled'] = True
                
                self.add_finding(Severity.INFO, "LAPS Configuration", 
                               "LAPS is Configured",
                               f"Local Administrator Password Solution (LAPS) is configured on {len(laps_computers)} computers." +
                               "\n\n**Benefits:**" +
                               "\n• Unique local admin passwords per computer" +
                               "\n• Automatic password rotation" +
                               "\n• Centralized password management")
            
            if non_laps_computers:
                self.add_finding(Severity.MEDIUM, "LAPS Configuration", 
                               "LAPS Not Configured on All Computers",
                               f"LAPS is not configured on {len(non_laps_computers)} computers: " +
                               ", ".join(non_laps_computers[:10]) +
                               "\n\n**Risk:** Computers without LAPS may have weak or shared local administrator passwords." +
                               "\n\n**Recommendation:** Deploy LAPS to all domain-joined computers.")
            
        except Exception as e:
            self.print_colored(f"⚠️ Error checking LAPS configuration: {e}", Colors.YELLOW)
        
        return results

    def run_security_checks(self) -> Dict[str, Any]:
        """Run all security protocol and configuration checks"""
        if self.skip_security_checks:
            self.print_colored("⏭️ Skipping security checks as requested", Colors.YELLOW)
            return {}
        
        self.print_colored("🔒 Starting security protocol and configuration checks...", Colors.BLUE)
        
        security_results = {
            'llmnr_nbtns': self.check_llmnr_nbtns_configuration(),
            'smb': self.check_smb_configuration(),
            'ntlm': self.check_ntlm_configuration(),
            'ldap': self.check_ldap_security(),
            'cpasswords': self.extract_cpasswords(),
            'ad_cs': self.check_ad_cs_vulnerabilities(),
            'dns': self.check_dns_security(),
            'kerberos': self.check_kerberos_security(),
            'account_security': self.check_account_security(),
            'network_security': self.check_network_security(),
            'laps': self.check_laps_configuration()
        }
        
        self.print_colored("✅ Security checks completed", Colors.GREEN)
        return security_results

    def _generate_security_checks_html(self, security_results: Dict[str, Any]) -> str:
        """Generate HTML for security check results"""
        if not security_results:
            return '<div class="no-data">No security check results available.</div>'
        
        html_parts = []
        
        # LLMNR/NBT-NS Configuration
        if 'llmnr_nbtns' in security_results:
            llmnr_data = security_results['llmnr_nbtns']
            html_parts.append(f"""
                <div class="policy-section">
                    <h4>🌐 LLMNR/NBT-NS Configuration</h4>
                    <div class="policy-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Status</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="manual">
                                    <td>LLMNR Protocol</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                                <tr class="manual">
                                    <td>NBT-NS Protocol</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
        
        # SMB Configuration
        if 'smb' in security_results:
            smb_data = security_results['smb']
            html_parts.append(f"""
                <div class="policy-section">
                    <h4>💾 SMB Configuration</h4>
                    <div class="policy-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Status</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="{'high' if smb_data.get('smbv1_enabled') else 'good'}">
                                    <td>SMBv1 Protocol</td>
                                    <td>{'Enabled (Vulnerable)' if smb_data.get('smbv1_enabled') else 'Disabled (Secure)'}</td>
                                    <td>{'High' if smb_data.get('smbv1_enabled') else 'Low'}</td>
                                </tr>
                                <tr class="manual">
                                    <td>SMB Signing</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
        
        # NTLM Configuration
        if 'ntlm' in security_results:
            html_parts.append(f"""
                <div class="policy-section">
                    <h4>🔐 NTLM Configuration</h4>
                    <div class="policy-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Status</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="manual">
                                    <td>NTLMv1</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                                <tr class="manual">
                                    <td>NTLMv2</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
        
        # LDAP Security
        if 'ldap' in security_results:
            ldap_data = security_results['ldap']
            html_parts.append(f"""
                <div class="policy-section">
                    <h4>📋 LDAP Security</h4>
                    <div class="policy-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Status</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="{'high' if not ldap_data.get('ldaps_enabled') else 'good'}">
                                    <td>LDAPS (SSL/TLS)</td>
                                    <td>{'Not used (Insecure)' if not ldap_data.get('ldaps_enabled') else 'Enabled (Secure)'}</td>
                                    <td>{'High' if not ldap_data.get('ldaps_enabled') else 'Low'}</td>
                                </tr>
                                <tr class="manual">
                                    <td>LDAP Signing</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                                <tr class="manual">
                                    <td>Channel Binding</td>
                                    <td>Manual verification required</td>
                                    <td>Medium</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
        
        # cPasswords
        if 'cpasswords' in security_results:
            cpasswords = security_results['cpasswords']
            if cpasswords:
                # Check if any passwords were actually decrypted
                decrypted_passwords = [cpwd for cpwd in cpasswords if cpwd.get('status') == 'decrypted' and cpwd.get('password')]
                manual_check_passwords = [cpwd for cpwd in cpasswords if cpwd.get('status') == 'requires_manual_check']
                
                if decrypted_passwords:
                    html_parts.append(f"""
                        <div class="policy-section">
                            <h4>🔑 Decrypted GPO cPasswords</h4>
                            <div class="policy-table">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>GPO Name</th>
                                            <th>Username</th>
                                            <th>Password</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {''.join([f'''
                                        <tr class="high">
                                            <td>{cpwd.get('gpo_display', 'Unknown')}</td>
                                            <td>{cpwd.get('username', 'Unknown')}</td>
                                            <td><code>{cpwd.get('password', 'Unknown')}</code></td>
                                            <td>Decrypted</td>
                                        </tr>
                                        ''' for cpwd in decrypted_passwords])}
                                    </tbody>
                                </table>
                            </div>
                            <p style="margin-top: 10px; font-size: 0.9em; color: #dc3545;">
                                <strong>⚠️ CRITICAL:</strong> {len(decrypted_passwords)} decrypted passwords found! These credentials should be immediately rotated.
                            </p>
                        </div>
                    """)
                
                # Add section for all cPassword locations found
                all_cpasswords = security_results.get('all_cpasswords', [])
                if all_cpasswords:
                    html_parts.append(f"""
                        <div class="policy-section">
                            <h4>🔍 All cPassword Locations Found</h4>
                            <div class="policy-table">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>GPO Name</th>
                                            <th>Location</th>
                                            <th>Status</th>
                                            <th>Decryption Error</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {''.join([f'''
                                        <tr class="{'high' if cpwd.get('status') == 'decrypted' else 'manual'}">
                                            <td>{cpwd.get('gpo_display', 'Unknown')}</td>
                                            <td><code>{cpwd.get('location', 'Unknown')}</code></td>
                                            <td>{cpwd.get('status', 'Unknown')}</td>
                                            <td>{cpwd.get('decryption_error', 'None')}</td>
                                        </tr>
                                        ''' for cpwd in all_cpasswords[:20]])}
                                    </tbody>
                                </table>
                            </div>
                            <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                                <strong>Summary:</strong> Found {len(all_cpasswords)} cPassword entries in total. {len(decrypted_passwords)} successfully decrypted, {len(all_cpasswords) - len(decrypted_passwords)} failed to decrypt.
                            </p>
                            <p style="margin-top: 5px; font-size: 0.9em; color: #ffc107;">
                                <strong>Decryption Issues:</strong> Common reasons for decryption failure include incorrect domain SID, corrupted cPassword values, or different encryption methods.
                            </p>
                        </div>
                    """)
                
                if manual_check_passwords:
                    html_parts.append(f"""
                        <div class="policy-section">
                            <h4>🔍 GPOs Requiring Manual Check</h4>
                            <div class="policy-table">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>GPO Name</th>
                                            <th>Status</th>
                                            <th>Files Checked</th>
                                            <th>Error (if any)</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {''.join([f'''
                                        <tr class="manual">
                                            <td>{cpwd.get('gpo_display', 'Unknown')}</td>
                                            <td>Requires manual check</td>
                                            <td>{cpwd.get('files_checked_count', len(cpwd.get('checked_files', [])))} XML files checked<br><small>Base: {cpwd.get('location', 'Unknown')}</small></td>
                                            <td>{cpwd.get('error', 'No error - no cPasswords found')}</td>
                                        </tr>
                                        ''' for cpwd in manual_check_passwords[:10]])}
                                    </tbody>
                                </table>
                            </div>
                            <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                                <strong>Note:</strong> {len(manual_check_passwords)} GPOs require manual verification. The script searched ALL XML files recursively but couldn't find cPasswords.
                            </p>
                            <p style="margin-top: 5px; font-size: 0.9em; color: #ffc107;">
                                <strong>Why manual check needed:</strong> Network access restrictions, file permissions, or cPasswords stored in non-standard locations.
                            </p>
                            <p style="margin-top: 5px; font-size: 0.9em; color: #17a2b8;">
                                <strong>Search Coverage:</strong> Script now searches ALL XML files in each GPO recursively, including Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, IniFiles.xml, Registry.xml, Shortcuts.xml, StartMenu.xml, and WindowsSettings.xml.
                            </p>
                        </div>
                    """)
        
        # AD CS Vulnerabilities
        if 'ad_cs' in security_results:
            ad_cs_data = security_results['ad_cs']
            if ad_cs_data.get('vulnerable_templates'):
                html_parts.append(f"""
                    <div class="policy-section">
                        <h4>🏛️ AD CS Vulnerabilities</h4>
                        <div class="policy-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Template Name</th>
                                        <th>Vulnerability</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {''.join([f'''
                                    <tr class="high">
                                        <td>{template.get('display_name', 'Unknown')}</td>
                                        <td>{template.get('vulnerability', 'Unknown')}</td>
                                        <td>{template.get('description', 'Unknown')}</td>
                                    </tr>
                                    ''' for template in ad_cs_data['vulnerable_templates'][:10]])}
                                </tbody>
                            </table>
                        </div>
                        <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                            <strong>Note:</strong> {len(ad_cs_data['vulnerable_templates'])} vulnerable templates found out of {ad_cs_data.get('templates_found', 0)} total templates.
                        </p>
                    </div>
                """)
        
        # Kerberos Security
        if 'kerberos' in security_results:
            kerberos_data = security_results['kerberos']
            if kerberos_data.get('unconstrained_delegation') or kerberos_data.get('preauth_disabled'):
                html_parts.append(f"""
                    <div class="policy-section">
                        <h4>🎫 Kerberos Security</h4>
                        <div class="policy-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Issue</th>
                                        <th>Count</th>
                                        <th>Risk Level</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {f'''
                                    <tr class="high">
                                        <td>Unconstrained Delegation</td>
                                        <td>{len(kerberos_data.get('unconstrained_delegation', []))}</td>
                                        <td>High</td>
                                    </tr>
                                    ''' if kerberos_data.get('unconstrained_delegation') else ''}
                                    {f'''
                                    <tr class="high">
                                        <td>Pre-authentication Disabled</td>
                                        <td>{len(kerberos_data.get('preauth_disabled', []))}</td>
                                        <td>High</td>
                                    </tr>
                                    ''' if kerberos_data.get('preauth_disabled') else ''}
                                </tbody>
                            </table>
                        </div>
                    </div>
                """)
        
        # LAPS Configuration
        if 'laps' in security_results:
            laps_data = security_results['laps']
            html_parts.append(f"""
                <div class="policy-section">
                    <h4>🔐 LAPS Configuration</h4>
                    <div class="policy-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Setting</th>
                                    <th>Status</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="{'good' if laps_data.get('laps_enabled') else 'weak'}">
                                    <td>LAPS Enabled</td>
                                    <td>{'Yes' if laps_data.get('laps_enabled') else 'No'}</td>
                                    <td>{laps_data.get('computers_with_laps', 0)} computers</td>
                                </tr>
                                <tr class="{'weak' if laps_data.get('computers_without_laps', 0) > 0 else 'good'}">
                                    <td>LAPS Not Configured</td>
                                    <td>{'Yes' if laps_data.get('computers_without_laps', 0) > 0 else 'No'}</td>
                                    <td>{laps_data.get('computers_without_laps', 0)} computers</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            """)
            
            # Add detailed list of computers with LAPS
            if laps_data.get('computers_with_laps_list'):
                computers_with_laps = laps_data['computers_with_laps_list']
                html_parts.append(f"""
                    <div class="data-section">
                        <div class="collapsible-section">
                            <h2 class="section-header" onclick="toggleSection(this)">✅ Computers With LAPS ({len(computers_with_laps)})</h2>
                            <div class="section-content">
                                <div class="search-container">
                                    <input type="text" class="search-box" id="lapsWithSearch" placeholder="🔍 Search computers with LAPS...">
                                </div>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Computer Name</th>
                                            <th>Status</th>
                                            <th>Risk Level</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {''.join([f'''
                                        <tr class="good">
                                            <td>{computer}</td>
                                            <td>LAPS Configured</td>
                                            <td>Low</td>
                                        </tr>
                                        ''' for computer in computers_with_laps[:50]])}
                                    </tbody>
                                </table>
                                {f'<p style="margin-top: 10px; font-size: 0.9em; color: #666;">Showing first 50 computers. Total: {len(computers_with_laps)} computers with LAPS configured.</p>' if len(computers_with_laps) > 50 else ''}
                            </div>
                        </div>
                    </div>
                """)
            
            # Add detailed list of computers without LAPS
            if laps_data.get('computers_without_laps_list'):
                computers_list = laps_data['computers_without_laps_list']
                html_parts.append(f"""
                    <div class="data-section">
                        <div class="collapsible-section">
                            <h2 class="section-header" onclick="toggleSection(this)">🖥️ Computers Without LAPS ({len(computers_list)})</h2>
                            <div class="section-content">
                                <div class="search-container">
                                    <input type="text" class="search-box" id="lapsSearch" placeholder="🔍 Search computers without LAPS...">
                                </div>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Computer Name</th>
                                            <th>Status</th>
                                            <th>Risk Level</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {''.join([f'''
                                        <tr class="weak">
                                            <td>{computer}</td>
                                            <td>LAPS Not Configured</td>
                                            <td>Medium</td>
                                        </tr>
                                        ''' for computer in computers_list])}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                """)
        
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
        
        # Run security protocol and configuration checks
        security_results = self.run_security_checks()
        
        # Update computer data with LAPS information
        if 'laps' in security_results and computers:
            laps_data = security_results['laps']
            computers_with_laps = set(laps_data.get('computers_with_laps_list', []))
            computers_without_laps = set(laps_data.get('computers_without_laps_list', []))
            
            for computer in computers:
                computer_name = computer.get('name', '')
                if computer_name in computers_with_laps:
                    computer['laps_status'] = '<span class="badge laps-yes">Yes</span>'
                elif computer_name in computers_without_laps:
                    computer['laps_status'] = '<span class="badge laps-no">No</span>'
                else:
                    computer['laps_status'] = '<span class="badge user">Unknown</span>'
        
        # Add security results to findings data
        findings_data['security_results'] = security_results
        
        # Add all cPasswords for detailed reporting
        if 'cpasswords' in security_results:
            findings_data['all_cpasswords'] = security_results['cpasswords']
        
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
    parser.add_argument('--skip-security-checks', action='store_true',
                       help='Skip security protocol and configuration checks (LLMNR, SMB, NTLM, etc.)')
    
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
        hash=args.hash,
        skip_security_checks=args.skip_security_checks
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