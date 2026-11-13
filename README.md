# LinuxSecure - CIS Benchmark Hardening & Automated Remediation Engine

LinuxSecure is a security auditing and automated system hardening platform designed for enterprise Linux infrastructure. Built with Python 3.11, FastAPI, and SQLite WAL, LinuxSecure evaluates server hosts against the Center for Internet Security (CIS) Distribution-Independent Linux Benchmarks, identifying configuration drift and automatically synthesizing executable bash remediation scripts.

## Core Capabilities
- **CIS Linux Benchmark Evaluation:** Evaluates 10 core benchmarks across System Configuration, Network Hardening, Logging/Auditing, and Access Control/SSH.
- **Kernel Sysctl Hardening:** Audits critical kernel parameters (`fs.suid_dumpable`, `net.ipv4.ip_forward`, `net.ipv4.conf.all.accept_redirects`, `net.ipv4.conf.all.accept_source_route`).
- **OpenSSH Daemon Hardening:** Enforces `PermitRootLogin no`, `PasswordAuthentication no`, and strict brute-force retry policies (`MaxAuthTries <= 4`).
- **File System Permissions Audit:** Verifies POSIX permissions on `/etc/shadow` (0600) and world-writable directories.
- **Automated Remediation Script Synthesis:** Generates a deterministic, idempotent Bash script (`harden_system.sh`) executing necessary `sysctl`, `sed`, `chmod`, and `systemctl` commands.

## Technology Stack
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, Pytest
- **Database:** SQLite (WAL mode)
- **Frontend:** Vanilla JavaScript, Modern CSS Flex/Grid, Dark SecOps UI
- **DevOps:** Docker, Docker Compose, GitHub Actions CI

## Quickstart

```bash
# Clone the repository
git clone https://github.com/Soulofghost/linuxsecure.git
cd linuxsecure

# Install dependencies
pip install -r backend/requirements.txt

# Run test suite
pytest -v

# Run local API service
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoints
- `GET /api/health` - Service health and CIS benchmark evaluator status.
- `GET /api/stats` - Assessment metrics, average compliance score, and critical failures.
- `GET /api/rules` - Full catalog of registered CIS Linux Benchmark rules.
- `POST /api/assess` - Execute a security benchmark assessment on a host profile.
- `GET /api/assessments` - Retrieve historical host assessment logs.
- `GET /api/assessments/{id}/remediation` - Download the generated bash remediation script.

## Author
Alvin MS ([@Soulofghost](https://github.com/Soulofghost))
