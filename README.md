# 🔍 AD Recon - Active Directory Security Reconnaissance Tool

A comprehensive Active Directory reconnaissance tool that performs deep security analysis, credential discovery, and vulnerability assessment with detailed risk reporting and advanced enumeration capabilities.

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/yourusername/ad-recon)

## 🚀 Features

### 🔐 **Authentication & Enumeration**
- **Multiple Authentication Methods**: SIMPLE, NTLM, DIGEST_MD5
- **Flexible Username Formats**: `domain\username`, `username@domain`, `username`, `short_domain\username`
- **Comprehensive User Enumeration**: All users, domain admins, service accounts
- **Advanced Group Analysis**: All groups, interesting groups, group membership analysis with missing user discovery
- **Computer & Printer Enumeration**: Network topology mapping with IP resolution
- **GPO Analysis**: Group Policy Object enumeration and analysis
- **Network Subnet Analysis**: Automatic /24 subnet organization and mapping

### 🔍 **Advanced Security Analysis**
- **Credential Discovery**: Password patterns in user descriptions with comprehensive filtering
- **Kerberoasting Detection**: Service Principal Names (SPNs) identification and analysis
- **AS-REP Roasting**: Pre-authentication vulnerability detection
- **Password Policy Analysis**: Domain-wide security policy assessment with risk evaluation
- **Account Security Analysis**: Old passwords, never logon users, inactive accounts
- **Privileged Account Analysis**: adminCount=1 accounts, service accounts with elevated privileges
- **Service Account Security**: Identification and analysis of service accounts
- **Comprehensive Risk Assessment**: 15+ security risk categories with detailed explanations

### 📊 **Advanced Reporting & UI**
- **Interactive HTML Reports**: Searchable, sortable, collapsible sections
- **Risk Categorization**: HIGH, MEDIUM, INFO severity levels with color coding
- **Detailed Risk Explanations**: Why each finding is dangerous and how attackers can exploit it
- **Incremental Saving**: Real-time data collection and saving
- **Multiple Export Formats**: JSON, CSV, TXT exports
- **Live Search Counts**: Dynamic result counting during searches
- **Column Sorting & Resizing**: Interactive table features
- **All Sections Collapsed by Default**: Clean, organized report view

### 🛡️ **Enhanced Security Features**
- **Comprehensive Risk Analysis**: 15+ security risk categories
- **Password Policy Assessment**: Security best practices validation with detailed analysis
- **Account Activity Analysis**: Old passwords, inactive accounts, never logon users
- **Service Account Security**: Elevated privilege account identification and analysis
- **Network Security**: Subnet analysis and computer enumeration
- **Group Enumeration for Missing Users**: Finds users beyond LDAP 1000-user limit
- **Failed User Lookup Tracking**: Separate file for failed user retrievals
- **Username List Generation**: Clean username list for password spraying attacks

## 📦 Installation

### Option 1: Download Pre-compiled Executable (Recommended)
```bash
# Download the latest release from GitHub
# Windows: ad_recon.exe
# Linux/macOS: ad_recon

# Run directly (no installation required)
./ad_recon.exe --mode full --dc-ip <DC_IP> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD>
```

### Option 2: Python Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/ad-recon.git
cd ad-recon

# Install dependencies
pip install -r requirements.txt

# Run the script
python ad_recon.py --mode full --dc-ip <DC_IP> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD>
```

### Option 3: Build from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/ad-recon.git
cd ad-recon

# Install dependencies
pip install -r requirements.txt

# Build executable (requires pyinstaller)
pip install pyinstaller
pyinstaller --onefile --name ad_recon ad_recon.py

# The executable will be in dist/ad_recon.exe
```

## 🎯 Usage

### Basic Usage
```bash
# Full reconnaissance mode (with credentials)
ad_recon.exe --mode full --dc-ip 192.168.1.10 --domain example.local --username user --password password

# Guest mode (no credentials - limited enumeration)
ad_recon.exe --mode guest --dc-ip 192.168.1.10 --domain example.local

# User inspection mode (single user analysis)
ad_recon.exe --mode inspect --dc-ip 192.168.1.10 --domain example.local --username user --password password --target-user admin
```

### Command Line Options
```
--mode          Reconnaissance mode: full, guest, inspect
--dc-ip         Domain Controller IP address
--domain        Domain name (FQDN or short name)
--username      Username for authentication
--password      Password for authentication
--hash          NTLM hash for authentication (instead of password)
--target-user   Target user for inspection mode
```

### Examples
```bash
# Full domain reconnaissance
ad_recon.exe --mode full --dc-ip 10.0.0.1 --domain corp.local --username admin --password Password123

# Anonymous enumeration
ad_recon.exe --mode guest --dc-ip 10.0.0.1 --domain corp.local

# Single user analysis
ad_recon.exe --mode inspect --dc-ip 10.0.0.1 --domain corp.local --username admin --password Password123 --target-user john.doe

# Using NTLM hash
ad_recon.exe --mode full --dc-ip 10.0.0.1 --domain corp.local --username admin --hash aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
```

## 📋 What It Discovers

### 🔍 **Comprehensive User Analysis**
- **All Domain Users**: Complete enumeration with detailed attributes
- **Domain Administrators**: Privileged account identification and analysis
- **Service Accounts**: Elevated privilege accounts with security analysis
- **Users with Old Passwords**: Accounts with passwords >90 days old
- **Users Who Never Logged On**: Accounts that have never been used
- **Users with Old Last Logon**: Inactive accounts >180 days
- **Accounts with Password Not Required**: Critical security vulnerability
- **Accounts with Password Never Expires**: Security risk accounts
- **Accounts with adminCount=1**: Protected administrative accounts
- **Missing Users**: Users found via group enumeration beyond LDAP limits
- **Username Lists**: Clean username lists for password spraying attacks

### 🔐 **Advanced Credential Discovery**
- **Passwords in Descriptions**: Pattern-based credential detection
- **Kerberoasting Candidates**: Accounts with Service Principal Names (SPNs)
- **AS-REP Roasting Candidates**: Accounts with DONT_REQ_PREAUTH flag
- **Password Patterns**: Comprehensive credential pattern analysis
- **Filtered Results**: Built-in account and computer/domain filtering

### 🏢 **Complete Domain Structure Analysis**
- **All Groups**: Complete group enumeration with member analysis
- **Interesting Groups**: Groups containing admin, super, service keywords
- **Group Policy Objects**: GPO enumeration and suspicious name detection
- **Computers**: Complete computer inventory with IP resolution
- **Printers**: Network printer discovery and analysis
- **Network Subnets**: Automatic /24 subnet organization and mapping
- **Network Topology**: Complete network infrastructure mapping

### 🛡️ **Comprehensive Security Assessment**
- **Password Policy Analysis**: Complete domain password policy evaluation
- **Account Lockout Settings**: Security policy assessment
- **Security Misconfigurations**: Automated vulnerability detection
- **Risk Categorization**: Detailed risk classification and explanations
- **Attack Vector Analysis**: How attackers can exploit each finding

## 📊 Advanced Report Features

### 🎨 **Interactive HTML Reports**
- **Collapsible Sections**: All sections collapsed by default for clean viewing
- **Real-Time Search**: Live search functionality with dynamic result counts
- **Column Sorting**: Sort any table by clicking column headers (A-Z, Z-A)
- **Column Resizing**: Adjustable column widths for better viewing
- **Color-Coded Severity**: Red (HIGH), Yellow (MEDIUM), Green (INFO)
- **Responsive Design**: Mobile-friendly layout and navigation

### 📈 **Comprehensive Data Export**
- **JSON Files**: Complete structured data export
- **CSV Files**: Tabular data for spreadsheet analysis
- **TXT Files**: Plain text lists and findings
- **HTML Reports**: Interactive web-based reports with all features

### 🔍 **Advanced Risk Analysis Categories**
1. **Credential Exposure**: Passwords in user descriptions with detailed analysis
2. **Password Security**: Old passwords, never expire, not required accounts
3. **Account Management**: Old logons, never logon users, inactive accounts
4. **Service Account Security**: Elevated privilege account identification
5. **Kerberoasting**: SPN vulnerabilities and attack vectors
6. **Privileged Accounts**: adminCount=1 accounts with security analysis
7. **Password Policy**: Domain-wide policy analysis with security assessment
8. **GPO Analysis**: Suspicious Group Policy Objects and security risks
9. **AS-REP Roasting**: Pre-authentication vulnerabilities
10. **Network Security**: Subnet analysis and computer enumeration
11. **Account Activity**: Comprehensive user activity analysis
12. **Security Misconfigurations**: Automated vulnerability detection

## 🚨 Advanced Security Features

### 🔐 **Comprehensive Password Policy Analysis**
- **Minimum Password Length**: Security assessment and recommendations
- **Maximum Password Age**: Expiration policy evaluation
- **Password History**: Previous password requirements analysis
- **Account Lockout Threshold**: Brute force protection assessment
- **Lockout Duration**: Security policy evaluation
- **Security Best Practices**: Automated validation and recommendations

### 🛡️ **Detailed Risk Explanations**
Each finding includes comprehensive analysis:
- **Why this is risky**: Technical explanation of the vulnerability
- **How attackers can exploit this**: Specific attack vectors and techniques
- **Severity level**: HIGH, MEDIUM, or INFO classification
- **Remediation guidance**: Security recommendations and best practices
- **Attack scenarios**: Real-world exploitation examples

### 🔍 **Advanced Enumeration Features**
- **Group-Based User Discovery**: Finds users beyond LDAP 1000-user limit
- **Missing User Analysis**: Comprehensive analysis of users found via groups
- **Failed User Tracking**: Separate tracking of failed user retrievals
- **Incremental Data Collection**: Real-time data saving and analysis
- **Comprehensive Error Handling**: Graceful error handling and reporting

## 📁 Complete Output Structure

```
output/
├── YYYYMMDD_HHMMSS/
│   ├── report.html              # Interactive HTML report with all features
│   ├── all_users.json           # Complete user data with all attributes
│   ├── domain_admins.json       # Domain admin data with security analysis
│   ├── all_groups.json          # Complete group enumeration data
│   ├── interesting_groups.json  # Groups with security-relevant names
│   ├── computers_with_ips.csv   # Complete computer inventory
│   ├── printers.csv             # Network printer data
│   ├── usernames.txt            # Clean username list for password spraying
│   ├── password_candidates.txt  # Discovered credentials and patterns
│   ├── kerberoast_candidates.txt # Kerberoasting targets
│   ├── asrep_candidates.txt     # AS-REP roasting targets
│   ├── subnets.json            # Network subnet analysis
│   ├── password_policy.json    # Domain password policy analysis
│   ├── failed_user_lookups.txt # Failed user retrievals (hidden from report)
│   ├── old_logon_users.json    # Users with old last logon
│   ├── old_password_users.json # Users with old passwords
│   └── never_logon_users.json  # Users who never logged on
```

## 🔧 Advanced Technical Details

### 🔐 **Enhanced Authentication Methods**
- **SIMPLE**: Standard username/password authentication
- **NTLM**: Windows NT LAN Manager authentication
- **DIGEST_MD5**: Challenge-response authentication
- **Hash-based**: NTLM hash authentication
- **Multiple Username Formats**: Flexible authentication options

### 🌐 **Advanced Network Discovery**
- **FQDN Resolution**: Automatic domain name discovery
- **IP Resolution**: Computer name to IP mapping
- **Subnet Analysis**: /24 subnet organization and mapping
- **Network Topology**: Complete computer and printer mapping
- **DNS Resolution**: Comprehensive name resolution

### 📊 **Advanced Data Collection**
- **LDAP Queries**: Comprehensive Active Directory enumeration
- **Group Enumeration**: All groups and member analysis
- **Missing User Discovery**: Users beyond LDAP limits via group analysis
- **Incremental Saving**: Real-time data collection and saving
- **Error Handling**: Comprehensive error handling and reporting
- **Performance Optimization**: Efficient data collection and processing

### 🔍 **Advanced Security Analysis**
- **Pattern Recognition**: Advanced credential pattern detection
- **Risk Assessment**: Comprehensive security risk evaluation
- **Vulnerability Analysis**: Automated vulnerability detection
- **Attack Vector Mapping**: Detailed attack scenario analysis
- **Security Best Practices**: Automated security validation

## ⚠️ Legal and Ethical Use

This tool is designed for:
- **Security professionals** conducting authorized security assessments
- **Penetration testers** performing legitimate security testing
- **System administrators** auditing their own domains
- **Security researchers** with proper authorization
- **Red team operators** conducting authorized assessments

**⚠️ Important**: Only use this tool on domains you own or have explicit permission to test. Unauthorized reconnaissance may be illegal.

## 🚀 Performance & Scalability

### **Large Environment Support**
- **Efficient Enumeration**: Optimized for large Active Directory environments
- **Memory Management**: Efficient memory usage for large datasets
- **Incremental Processing**: Real-time data processing and saving
- **Error Recovery**: Graceful handling of large-scale enumeration

### **Advanced Features**
- **Group-Based Discovery**: Finds users beyond standard LDAP limits
- **Comprehensive Analysis**: Complete security analysis of all discovered data
- **Interactive Reporting**: Advanced HTML reports with all features
- **Multiple Export Formats**: Flexible data export options

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**🔍 AD Recon** - Comprehensive Active Directory Security Reconnaissance Tool with Advanced Enumeration and Analysis Capabilities 