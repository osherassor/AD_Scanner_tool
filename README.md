<h1 align="center">🏢 AD Scanner</h1>

<p align="center">
  <strong>Walk into an Active Directory environment and walk out with a security report.</strong><br>
  Domain enumeration, privilege analysis, password policy review, AD CS / Kerberos / LDAP / DNS / LAPS checks, and a full HTML report — all from one Python tool.
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/osherassor/AD_Scanner_tool?style=for-the-badge&logo=github&color=ffd700" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/osherassor/AD_Scanner_tool?style=for-the-badge&logo=git&color=00d4aa" alt="Last commit">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-informational?style=for-the-badge" alt="License">
</p>

---

## What is this?

An AD reconnaissance + assessment tool that pulls a full picture of a domain — users, groups, computers, GPOs, password policy, privileged accounts, Kerberos exposures, AD CS misconfigs, LAPS state, and more — then writes it up as a searchable HTML report you can hand a client.

Three modes:

| Mode | When to use |
|---|---|
| **`guest`** | Anonymous / null-bind probing — what does an unauthenticated attacker see? |
| **`full`** | Authenticated assessment with creds (or NTLM hash) — the deep dive |
| **`inspect`** | Drill into a single user account |

## 🚀 Quick start

```bash
git clone https://github.com/osherassor/AD_Scanner_tool
cd AD_Scanner_tool
pip install -r requirements.txt

# Authenticated full scan
python ad_recon.py --mode full \
  --dc-ip 192.168.1.10 --domain example.local \
  --username admin --password 'Password123!'
```

## ✨ What it checks

### 🔎 Reconnaissance

- **Domain** — structure, trusts, FSMO roles
- **Users** — enumeration with security flags (`adminCount`, password-not-required, SPNs, `DONT_REQ_PREAUTH`…)
- **Groups** — membership, privilege chains, nested groups
- **Computers** — devices with IP resolution
- **Printers** — discovered network printers
- **GPOs** — full GPO enumeration

### 🛡️ Security assessment

- 👑 **Privileged accounts** — `adminCount=1`, service accounts with elevated privs
- 🔑 **Password policy** — domain policy assessment + recommendations
- 🔒 **Account security** — lockout policies, password ages, security settings
- 🎫 **Kerberos** — AS-REP roasting + Kerberoasting candidate detection
- 👤 **Service accounts** — SPN-bearing accounts surfaced for review

### 🔬 Advanced checks

- 📡 **Network protocols** — LLMNR, NBT-NS, SMB, NTLM configuration
- 🔐 **LDAP** — LDAPS, signing, channel binding
- 🔓 **GPO cPasswords** — detection + decryption attempts
- 📜 **AD CS (ESC1–ESC8)** — certificate-services vulnerability assessment
- 🎭 **Kerberos delegation** — unconstrained delegation detection
- 🔑 **LAPS** — Local Administrator Password Solution coverage
- 🌐 **DNS** — zone transfers, recursion settings

### 🔐 Credential exposure

- 📝 **Passwords in `description` fields** — classic find, surprisingly common
- ⚠️ **Domain admin credential exposure** — high-severity hits
- 🧩 **User credential patterns** — heuristics for accidentally-stored creds
- 📊 **Consolidated risk cards** — every finding gets a severity + exploitation guide

## 🎯 Usage

```bash
# Anonymous / guest probe
python ad_recon.py --mode guest --dc-ip 192.168.1.10 --domain example.local

# Authenticated full scan with creds
python ad_recon.py --mode full --dc-ip 192.168.1.10 --domain example.local \
  --username admin --password 'Password123!'

# Authenticated with hash
python ad_recon.py --mode full --dc-ip 192.168.1.10 --domain example.local \
  --username admin --hash aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99

# Drill into one user
python ad_recon.py --mode inspect --dc-ip 192.168.1.10 --domain example.local \
  --username admin --password 'Password123!' --target-user john.doe
```

### CLI reference

| Option | Required | Description |
|---|---|---|
| `--mode` | yes | `guest`, `full`, or `inspect` |
| `--dc-ip` | yes | Domain Controller IP |
| `--domain` | yes | Domain (e.g. `corp.local`) |
| `--username` | full / inspect | Auth username |
| `--password` | one of | Auth password |
| `--hash` | one of | NTLM hash (alternative to password) |
| `--skip-security-checks` | no | Skip the advanced security protocol checks (faster) |

## 📤 Output

### HTML report

- 📈 Executive summary — domain stats, top findings
- ⚠️ Risk assessment — severity-categorized findings with exploitation notes
- 📋 Searchable, collapsible tables for every entity type
- 📜 Security-protocol analysis section
- 🔓 cPassword extraction results
- 🔑 LAPS coverage map

### Data exports

- 🧾 **JSON** — full structured data for further automation
- 📊 **CSV** — tabular for spreadsheets
- 📄 **TXT** — username lists ready for password spraying

## 🛠️ Requirements

- Python 3.8+
- Network access to a DC
- See `requirements.txt`

## 🤝 Pairs well with

- 🔉 **[LANWhisper](https://github.com/osherassor/LANWhisper)** — recon DNS first to find the DC and management hosts, then point AD_Scanner at the DC.
- 🗂️ **[smb_files_scanner](https://github.com/osherassor/smb_files_scanner)** — once you have a domain user, run this against discovered file servers to harvest secrets from shares.
- 📚 **[AwesomeWL — credentials](https://github.com/osherassor/AwesomeWL/blob/main/credentials/default_creds.md)** — for password spraying lists and default creds across vendors.

## ⚖️ Responsible use

Authorized assessments only — make sure AD scanning is in scope before you run this. The output is a roadmap to compromise; treat it like one.

## 📄 License

MIT
