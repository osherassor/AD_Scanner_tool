# AD Reconnaissance Tool

A comprehensive Active Directory reconnaissance and security assessment tool that provides detailed analysis of domain configurations, user accounts, security policies, and potential vulnerabilities.

## 🚀 Features

### Core Reconnaissance
- **Domain Information**: Complete domain structure analysis
- **User Enumeration**: Comprehensive user account analysis with security flags
- **Group Analysis**: Detailed group membership and privilege analysis
- **Computer Discovery**: Network device enumeration with IP resolution
- **Printer Discovery**: Network printer identification
- **GPO Analysis**: Group Policy Object enumeration and analysis

### Security Assessment
- **Privileged Account Analysis**: adminCount=1 accounts, service accounts with elevated privileges
- **Password Policy Analysis**: Domain password policy assessment and recommendations
- **Account Security**: Analysis of account lockout policies, password age, and security settings
- **Kerberos Security**: AS-REP roasting and Kerberoasting vulnerability detection
- **Service Account Identification**: Detection of accounts with Service Principal Names (SPNs)

### Advanced Security Checks
- **Network Protocol Security**: LLMNR, NBT-NS, SMB, and NTLM configuration analysis
- **LDAP Security**: LDAPS, signing, and channel binding assessment
- **cPassword Extraction**: Comprehensive GPO cPassword detection and decryption attempts
- **AD CS Vulnerabilities**: Certificate Services vulnerability assessment (ESC1-ESC8)
- **Kerberos Delegation**: Unconstrained delegation detection
- **LAPS Configuration**: Local Administrator Password Solution assessment
- **DNS Security**: Zone transfer and recursion configuration analysis

### Credential Analysis
- **Password in Description Detection**: Identifies credentials stored in user descriptions
- **Domain Admin Credential Exposure**: High-risk credential exposure in administrative accounts
- **User Credential Patterns**: Detection of potential credentials in regular user accounts
- **Consolidated Risk Reporting**: Organized risk cards with detailed exploitation guidance

### Reporting & Output
- **Comprehensive HTML Reports**: Professional, searchable, and collapsible HTML reports
- **Multiple Export Formats**: JSON, CSV, and TXT exports
- **Username Lists**: Password spraying candidate lists
- **Risk Severity Classification**: HIGH, MEDIUM, and INFO level findings
- **Detailed Exploitation Guidance**: Step-by-step attack scenarios and recommendations

## 📋 Requirements

- Python 3.8+
- Windows environment (for Active Directory access)
- Network access to domain controllers
- Required Python packages (see requirements.txt)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/AD_Reconnaissance_Tool.git
   cd AD_Reconnaissance_Tool
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool**:
   ```bash
   python ad_recon.py --mode full --dc-ip <DC_IP> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD>
   ```

## 🎯 Usage

### Modes

#### Guest Mode (Anonymous Access)
```bash
python ad_recon.py --mode guest --dc-ip 192.168.1.10 --domain example.local
```

#### Full Mode (Authenticated Access)
```bash
python ad_recon.py --mode full --dc-ip 192.168.1.10 --domain example.local --username admin --password "Password123!"
```

#### User Inspection Mode
```bash
python ad_recon.py --mode inspect --dc-ip 192.168.1.10 --domain example.local --username admin --password "Password123!" --target-user john.doe
```

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--mode` | Operation mode: guest, full, inspect | Yes |
| `--dc-ip` | Domain Controller IP address | Yes |
| `--domain` | Domain name (e.g., example.local) | Yes |
| `--username` | Username for authentication | For full/inspect modes |
| `--password` | Password for authentication | For full/inspect modes |
| `--hash` | NTLM hash for authentication | Alternative to password |
| `--skip-security-checks` | Skip advanced security protocol checks | No |

## 📊 Output

The tool generates comprehensive reports in multiple formats:

### HTML Report
- **Executive Summary**: High-level domain statistics and key findings
- **Risk Assessment**: Categorized security findings with severity levels
- **Detailed Tables**: Searchable and collapsible data tables
- **Security Protocol Analysis**: Network and authentication security assessment
- **cPassword Analysis**: GPO credential extraction results
- **LAPS Configuration**: Local administrator password management status

### Data Exports
- **JSON**: Complete structured data for programmatic analysis
- **CSV**: Tabular data for spreadsheet analysis
- **TXT**: Username lists for password spraying operations



## ⚠️ Disclaimer

This tool is designed for **authorized security testing and assessment only**. Always ensure you have proper authorization before using this tool against any Active Directory environment. The authors are not responsible for any misuse of this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📞 Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

---

**Note**: This tool requires appropriate permissions and authorization to access Active Directory environments. Always follow responsible disclosure practices and obtain proper authorization before conducting security assessments. 
