# 🐳 Docker Secret & CVE Scanner

A security-focused Docker image analyzer that scans images from Docker Hub for secrets, vulnerabilities, code issues, and metadata leaks — all with rich CLI UI and Discord alerting.

---

## 📌 Features

- 🔐 Secret detection (API keys, passwords, private keys, etc.)
- 🧠 Custom regex pattern support
- 🔍 CVE scanning with [Grype](https://github.com/anchore/grype)
- 🚨 Semgrep scan for source code issues
- 🧱 Docker image layer analysis (via container-diff)
- 📝 Docker history logging
- 🔗 GitHub metadata detection from image labels
- 📊 CLI progress bar with [Rich](https://github.com/Textualize/rich)
- 📩 Discord webhook alerts (separate channels for secure alerts)

---

## ⚙️ Requirements

- Python 3.8+
- Docker CLI
- [Semgrep](https://semgrep.dev/docs/cli-usage/)
- [Grype](https://github.com/anchore/grype)
- [container-diff](https://github.com/GoogleContainerTools/container-diff)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## 📂 File Structure

```bash
.
├── extracted_tags/         # Extracted file systems
├── semgrep_reports/        # JSON output from Semgrep
├── grype_reports/          # JSON output from Grype
├── layer_diff/             # container-diff analysis
├── history_logs/           # Docker history files
├── config.yaml             # Discord webhook config
└── scanner.py              # Main scanner script
```

---

## 🧪 Usage

```bash
python scanner.py --namespace <dockerhub-namespace> --repo <repository-name> --custom-secrets-file secrets.yaml
```

### Example

```bash
python scanner.py --namespace myteam --repo vulnerable-image --custom-secrets-file secrets.yaml
```

---

## 🔧 Configuration

### `config.yaml`

```yaml
webhook: "https://discord.com/api/webhooks/..."
secure_webhook: "https://discord.com/api/webhooks/..."  # For security-related alerts
```

### `secrets.yaml`

```yaml
patterns:
  - "apikey\s*[:=]\s*['\"]?[A-Za-z0-9]{32}['\"]?"
  - "secret\s*[:=]\s*['\"]?[A-Za-z0-9]{40}['\"]?"
```

---

## 🖥️ Screenshot

![terminal-ui](https://user-images.githubusercontent.com/your-repo/assets/cli-preview.png)

---

## 📬 Output Alerts

- Secret matches and critical vulnerabilities go to `secure_webhook`.
- General findings (Semgrep/code, metadata, diff reports) go to `webhook`.

---
