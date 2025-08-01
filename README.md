# 🧾 AD Recon - Active Directory Reconnaissance Tool

A comprehensive Python-based Active Directory reconnaissance tool that performs deep enumeration of AD objects, detects security misconfigurations, identifies credential exposure, and generates detailed reports in multiple formats.

## 🚀 Features

### 🔍 Reconnaissance Modes
- **Guest Mode**: Anonymous enumeration for initial assessment
- **Full Mode**: Comprehensive enumeration with authentication
- **User-Inspect Mode**: Detailed user account analysis

### 📊 Enumeration Capabilities
- **Users**: All user accounts with attributes, UAC flags, and security analysis
- **Groups**: Domain groups and membership analysis
- **Computers**: Workstations and servers with network resolution
- **GPOs**: Group Policy Objects enumeration
- **Printers**: Network printer discovery
- **Domain Admins**: Privileged account identification

### 🔒 Security Analysis
- **Kerberoasting Candidates**: Accounts with SPN vulnerable to Kerberoasting
- **AS-REP Roasting**: Accounts with DONT_REQ_PREAUTH flag
- **Credential Exposure**: Pattern-based search in user descriptions
- **Misconfigurations**: Stale accounts, adminCount=1, password policies
- **UAC Flag Analysis**: DONT_REQ_PREAUTH, PASSWD_NOTREQD, pwdNeverExpires

### 📈 Output Formats
- **JSON**: Structured data export
- **CSV**: Spreadsheet-compatible format
- **HTML**: Interactive web report with collapsible sections
- **TXT**: Plain text summary
- **Live Terminal**: Real-time colored output with severity indicators

## 📋 Requirements

- Python 3.7+
- Network access to Active Directory domain controller
- Appropriate permissions for the enumeration level

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ad-recon.git
cd ad-recon
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python ad_recon.py --help
```

## ⚡ Quick Start Guide

### Get Started in 5 Minutes

#### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 2. Test Installation
```bash
python ad_recon.py --help
```

#### 3. View Example Report
Open `example_report.html` to see the tool's capabilities.

#### 4. Run Your First Scan

**Guest Mode (Anonymous)**
```bash
python ad_recon.py --mode guest --dc-ip 192.168.1.10 --domain corp.local
```

**Full Mode (Authenticated)**
```bash
python ad_recon.py --mode full --dc-ip 192.168.1.10 --domain corp.local --username admin --password Password123
```

**User Inspection Mode**
```bash
python ad_recon.py --mode user-inspect --dc-ip 192.168.1.10 --domain corp.local --username admin --password Password123 --target-user john.doe
```

## 🎯 Detailed Usage

### Basic Usage
```bash
# Guest mode (anonymous)
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode guest

# Full mode with credentials
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode full --username user@corp.local --password password

# User inspection mode
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode user-inspect --username user@corp.local --password password
```

### Advanced Usage
```bash
# With NTLM hash authentication
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode full --username user@corp.local --ntlm-hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Custom output directory
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode full --username user@corp.local --password password --output-dir ./my_results

# Verbose output
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode full --username user@corp.local --password password --verbose
```

### Command Line Arguments

| Argument | Description | Required | Example |
|----------|-------------|----------|---------|
| `--domain` | Target domain name | Yes | `corp.local` |
| `--dc` | Domain controller hostname/IP | Yes | `dc01.corp.local` |
| `--mode` | Reconnaissance mode | Yes | `guest`, `full`, `user-inspect` |
| `--username` | Username for authentication | Mode dependent | `user@corp.local` |
| `--password` | Password for authentication | Mode dependent | `password123` |
| `--ntlm-hash` | NTLM hash for authentication | Mode dependent | `hash:hash` |
| `--output-dir` | Custom output directory | No | `./results` |
| `--verbose` | Enable verbose output | No | Flag |
| `--help` | Show help message | No | Flag |

### Reconnaissance Modes

#### 🚶 Guest Mode
- **Purpose**: Initial reconnaissance without authentication
- **Use Case**: External assessment, initial foothold
- **Limitations**: Limited data access, basic enumeration
- **Example**:
```bash
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode guest
```

#### 🔍 Full Mode
- **Purpose**: Comprehensive enumeration with authentication
- **Use Case**: Internal assessment, security audit
- **Features**: Complete object enumeration, security analysis
- **Example**:
```bash
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode full --username auditor@corp.local --password SecurePass123
```

#### 👤 User-Inspect Mode
- **Purpose**: Detailed user account analysis
- **Use Case**: User account security review
- **Features**: Deep user analysis, credential exposure detection
- **Example**:
```bash
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode user-inspect --username admin@corp.local --password AdminPass123
```

## 📊 Output Files

### Generated Files
- `ad_recon_YYYYMMDD_HHMMSS/` - Timestamped output directory
  - `ad_recon_report.html` - Interactive HTML report
  - `ad_recon_data.json` - Structured JSON data
  - `ad_recon_summary.csv` - CSV summary
  - `ad_recon_findings.txt` - Plain text findings
  - `errors.log` - Error log file

### HTML Report Features
- **Executive Summary**: Key statistics and metrics
- **Security Findings**: Categorized by severity (High/Medium/Info)
- **Data Tables**: Searchable tables for all enumerated objects
- **Collapsible Sections**: Interactive expand/collapse functionality
- **Responsive Design**: Mobile-friendly layout
- **Search Functionality**: Real-time filtering of data

## 🔍 Security Analysis Details

### Kerberoasting Detection
Identifies accounts with Service Principal Names (SPN) that are vulnerable to Kerberoasting attacks:
- Accounts with `servicePrincipalName` attribute
- Non-disabled user accounts
- Potential service accounts

### AS-REP Roasting Detection
Finds accounts vulnerable to AS-REP Roasting:
- Accounts with `DONT_REQ_PREAUTH` UAC flag
- Non-disabled user accounts
- Pre-authentication disabled accounts

### Credential Exposure Analysis
Searches user descriptions for potential credential exposure:
- Password patterns
- API keys
- Connection strings
- Hardcoded credentials

### Misconfiguration Detection
Identifies common security misconfigurations:
- Stale accounts (inactive for extended periods)
- Accounts with `adminCount=1`
- Accounts with `PASSWD_NOTREQD` flag
- Accounts with `pwdNeverExpires` flag

## 🎨 Live Output Features

### Color-Coded Severity
- 🔴 **HIGH**: Critical security findings
- 🟡 **MEDIUM**: Important security issues
- 🔵 **INFO**: Informational findings

### Real-Time Progress
- Connection status
- Enumeration progress
- Finding discoveries
- Error notifications

## 🛡️ Security Considerations

### Legal and Ethical Use
- **Authorized Testing Only**: Use only on systems you own or have explicit permission to test
- **Compliance**: Ensure compliance with local laws and regulations
- **Documentation**: Maintain proper documentation of testing activities

### Best Practices
- **Credential Security**: Use dedicated test accounts with minimal privileges
- **Network Isolation**: Test in isolated environments when possible
- **Data Handling**: Secure storage and disposal of sensitive data
- **Reporting**: Document findings and remediation recommendations

### Security Features
- **Input Validation**: All inputs are validated and sanitized
- **Error Handling**: Graceful error handling without information disclosure
- **Logging**: Secure logging practices
- **Authentication**: Secure authentication methods
- **Output Sanitization**: Sensitive data is properly handled in outputs

## 🔧 Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Check network connectivity
ping dc01.corp.local

# Verify LDAP port accessibility
telnet dc01.corp.local 389
```

#### Authentication Issues
```bash
# Verify credentials
python ad_recon.py --domain corp.local --dc dc01.corp.local --mode guest

# Check user permissions
# Ensure account has appropriate AD read permissions
```

#### Output Issues
```bash
# Check directory permissions
ls -la ./output/

# Verify Python dependencies
pip list | grep ldap3
```

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `Connection failed` | Network/DNS issue | Check connectivity and DNS resolution |
| `Invalid credentials` | Wrong username/password | Verify credentials and account status |
| `Insufficient privileges` | Lack of permissions | Use account with appropriate AD read access |
| `Module not found` | Missing dependencies | Run `pip install -r requirements.txt` |

## 🚀 Performance Optimization

### Large Environments
- **Batch Processing**: Process large datasets in batches
- **Memory Management**: Monitor memory usage for large enumerations
- **Network Optimization**: Use local DC when possible

### Customization
- **Filtering**: Modify search filters for specific requirements
- **Output Formats**: Customize output formats as needed
- **Analysis Rules**: Add custom security analysis rules

## 📁 Project Structure

```
ad-recon/
├── 📄 ad_recon.py              # Main reconnaissance script (50KB)
├── 📄 requirements.txt         # Python dependencies
├── 📄 README.md               # Main documentation
├── 📄 LICENSE                 # MIT License
├── 📄 .gitignore              # Git ignore patterns
└── 📄 example_report.html     # Example HTML report
```

### Core Scripts

#### `ad_recon.py`
- **Purpose**: Main Active Directory reconnaissance tool
- **Key Components**:
  - `Colors` class for terminal output styling
  - `Severity` enum for risk classification
  - `Finding` dataclass for structured findings
  - `ADRecon` main class with all functionality
  - LDAP connection and search methods
  - Enumeration methods for all AD objects
  - Security analysis and misconfiguration detection
  - Output generation (JSON, CSV, HTML, TXT)
  - Command-line argument parsing

#### `example_report.html`
- **Purpose**: Example HTML report showing tool capabilities
- **Key Components**:
  - Sample AD reconnaissance data
  - Interactive collapsible sections
  - Security findings examples
  - Responsive design demonstration

## 🤝 Contributing

### How to Contribute

#### Reporting Issues
- Use the GitHub issue tracker
- Provide detailed information about the problem
- Include steps to reproduce the issue
- Specify your environment (OS, Python version, etc.)

#### Feature Requests
- Describe the feature you'd like to see
- Explain the use case and benefits
- Consider implementation complexity

#### Code Contributions
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

#### Code Style
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for all functions and classes
- Keep functions focused and single-purpose

#### Error Handling
- Implement proper exception handling
- Provide meaningful error messages
- Log errors appropriately
- Gracefully handle edge cases

#### Security Considerations
- Validate all inputs
- Sanitize data before output
- Follow security best practices
- Consider potential attack vectors

#### Testing
- Add unit tests for new features
- Ensure existing tests pass
- Test edge cases and error conditions
- Verify functionality across different environments

### Development Setup

#### Prerequisites
- Python 3.7+
- Git
- Access to Active Directory test environment

#### Local Development
```bash
# Clone the repository
git clone https://github.com/yourusername/ad-recon.git
cd ad-recon

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements.txt

# Run linting
flake8 ad_recon.py
```

#### Testing Your Changes
```bash
# Test main script
python ad_recon.py --help

# View example report
# Open example_report.html in a web browser
```

### Security Guidelines

#### Code Review
- All contributions require review
- Security-sensitive changes need additional scrutiny
- Follow secure coding practices
- Consider potential vulnerabilities

#### Testing Security Features
- Test in isolated environments
- Use dedicated test accounts
- Follow responsible disclosure
- Document security considerations

## 🔒 Security Policy

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

### Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in AD Recon, please follow these guidelines:

#### Responsible Disclosure
1. **Do not publicly disclose the vulnerability** until it has been addressed
2. **Report the issue privately** using one of the methods below
3. **Provide detailed information** about the vulnerability
4. **Allow reasonable time** for the issue to be addressed

#### How to Report

**Preferred Method: GitHub Security Advisories**
1. Go to the [Security tab](https://github.com/yourusername/ad-recon/security) in the repository
2. Click "Report a vulnerability"
3. Fill out the security advisory form with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

**Alternative Method: Email**
If you prefer to report via email, send details to: `security@yourdomain.com`

#### Information to Include
When reporting a vulnerability, please provide:
- **Description**: Clear explanation of the vulnerability
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Impact**: Potential security implications
- **Environment**: OS, Python version, AD environment details
- **Proof of Concept**: Code or commands that demonstrate the issue
- **Suggested Fix**: Any ideas for addressing the vulnerability

#### Response Timeline
- **Initial Response**: Within 48 hours of receiving the report
- **Status Update**: Weekly updates on progress
- **Resolution**: Target resolution within 30 days for critical issues

#### Recognition
Security researchers who responsibly disclose vulnerabilities will be:
- Acknowledged in the security advisory
- Listed in the project's security hall of fame
- Given credit in release notes (with permission)

## 📋 Code of Conduct

### Our Pledge
We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards
Examples of behavior that contributes to a positive environment:
- Demonstrating empathy and kindness toward other people
- Being respectful of differing opinions, viewpoints, and experiences
- Giving and gracefully accepting constructive feedback
- Accepting responsibility and apologizing to those affected by our mistakes
- Focusing on what is best for the overall community

Examples of unacceptable behavior:
- The use of sexualized language or imagery, and sexual attention or advances of any kind
- Trolling, insulting or derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate in a professional setting

### Enforcement
Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the community leaders responsible for enforcement at `conduct@yourdomain.com`. All complaints will be reviewed and investigated promptly and fairly.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📝 Changelog

### [1.0.0] - 2024-12-02

#### Added
- Initial release of AD Recon tool
- Three reconnaissance modes: guest, full, and user-inspect
- Comprehensive Active Directory enumeration capabilities
  - Domain admins enumeration
  - All users enumeration with security analysis
  - Computers enumeration with IP resolution
  - Printers enumeration
  - Group Policy Objects enumeration
  - Groups enumeration
- Security analysis features
  - Kerberoasting candidate detection
  - AS-REP roasting candidate detection
  - Credential exposure analysis in user descriptions
  - Misconfiguration detection (stale accounts, adminCount=1, etc.)
  - UAC flag analysis
- Multiple output formats
  - Interactive HTML reports with collapsible sections
  - JSON data export
  - CSV summary files
  - Plain text findings
- Live terminal output with color-coded severity indicators
- Authentication methods
  - Anonymous bind (guest mode)
  - Username/password authentication
  - NTLM hash authentication
- Comprehensive error handling and logging
- Network resolution for computers and printers
- Pattern-based credential detection
- Executive summary with statistics
- Search functionality in HTML reports
- Responsive design for mobile compatibility

#### Features
- **Guest Mode**: Anonymous enumeration for initial assessment
- **Full Mode**: Comprehensive enumeration with authentication
- **User-Inspect Mode**: Detailed user account analysis
- **HTML Reports**: Interactive web reports with collapsible sections
- **Live Output**: Real-time colored terminal output
- **Security Analysis**: Automated detection of security issues
- **Multiple Formats**: JSON, CSV, HTML, and TXT outputs

#### Technical Details
- Built with Python 3.7+
- Uses ldap3 library for LDAP connectivity
- Implements proper error handling and logging
- Follows security best practices
- Includes comprehensive documentation

### [Unreleased]

#### Planned Features
- Additional authentication methods
- Enhanced reporting capabilities
- Performance optimizations
- Additional security analysis rules
- Integration with other security tools

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any network or system.

## 📞 Support

### Issues and Questions
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check this README for detailed information
- **Example Report**: Open `example_report.html` to see example output

### Community
- **Discussions**: Use GitHub Discussions for questions
- **Contributions**: Pull requests are welcome
- **Feedback**: Share your experience and suggestions

## 🏆 Acknowledgments

- **ldap3 Library**: For LDAP connectivity
- **Security Community**: For research and best practices
- **Contributors**: All who help improve this tool

---

**Happy Reconnaissance! 🕵️‍♂️** 