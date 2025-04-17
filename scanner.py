import os
import re
import json
import shutil
import argparse
import requests
import subprocess
import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

# Load configuration
parser = argparse.ArgumentParser(description="Docker Secret Scanner")
parser.add_argument("--namespace", required=True)
parser.add_argument("--repo", required=True)
parser.add_argument("--custom-secrets-file", type=str)
args = parser.parse_args()

NAMESPACE = args.namespace
REPO = args.repo
EXTRACT_DIR = "extracted_tags"
SEMGREP_REPORT_DIR = "semgrep_reports"

try:
    with open("config.yaml", 'r') as cfg:
        config = yaml.safe_load(cfg)
    DISCORD_WEBHOOK_URL = config.get("webhook")
    if not DISCORD_WEBHOOK_URL:
        raise ValueError("Missing 'webhook' in config.yaml")
except Exception as e:
    console.print(f"[red]Config load error: {e}[/red]")
    exit(1)

# Load custom secrets
CUSTOM_PATTERNS = []
if args.custom_secrets_file:
    if args.custom_secrets_file.endswith(".yaml"):
        with open(args.custom_secrets_file, 'r') as f:
            CUSTOM_PATTERNS = yaml.safe_load(f).get("patterns", [])
    else:
        with open(args.custom_secrets_file, 'r') as f:
            CUSTOM_PATTERNS = [line.strip() for line in f if line.strip()]

SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Generic API": r"(?i)(api[_-]?key|secret|token)[\"'\s:=]+([A-Za-z0-9_\-]{16,})",
    "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Password": r"(?i)(password|passwd|pwd)[\"'\s:=]+.{6,}"
}

def send_discord_embed(title, description, color=0xff0000, fields=None):
    embed = {"title": title, "description": description, "color": color, "fields": fields or []}
    payload = {"username": "Docker Scanner", "embeds": [embed]}
    requests.post(DISCORD_WEBHOOK_URL, json=payload)

def context(content, match):
    lines = content.splitlines()
    start_line = content[:match.start()].count('\n')
    end_line = content[:match.end()].count('\n')
    return "\n".join(lines[max(0, start_line-2):min(len(lines), end_line+3)])

def scan_file_for_secrets(filepath, tag):
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
        for label, pattern in SECRET_PATTERNS.items():
            match = re.search(pattern, content)
            if match:
                send_discord_embed(f"\U0001F510 {label} in {tag}", f"{filepath}\n```{context(content, match)}```", 0xffaa00)
        for pat in CUSTOM_PATTERNS:
            match = re.search(pat, content, re.IGNORECASE)
            if match:
                send_discord_embed(f"\U0001F9E0 Custom Match in {tag}", f"{filepath}\n```{context(content, match)}```", 0x00c3e3)

def scan_extracted_dir(dir_path, tag):
    for root, _, files in os.walk(dir_path):
        for f in files:
            if f.endswith((".env", ".json", ".js", ".ts", ".yaml", ".yml", ".ini", ".py")):
                scan_file_for_secrets(os.path.join(root, f), tag)

def run_semgrep(path, tag):
    report_path = os.path.join(SEMGREP_REPORT_DIR, f"{tag}.json")
    os.makedirs(SEMGREP_REPORT_DIR, exist_ok=True)
    subprocess.run(["semgrep", "scan", path, "--config", "auto", "--json", "--output", report_path])
    with open(report_path) as f:
        data = json.load(f)
    findings = data.get("results", [])
    if findings:
        fields = [{"name": r['check_id'], "value": f"{r['path']}:{r['start']['line']}", "inline": False} for r in findings[:5]]
        send_discord_embed(f"\U0001F6A8 Semgrep Findings in {tag}", f"{len(findings)} issues found", 0xff5555, fields)

def list_dockerhub_tags():
    tags, url = [], f"https://hub.docker.com/v2/repositories/{NAMESPACE}/{REPO}/tags?page_size=100"
    while url:
        res = requests.get(url).json()
        tags += [r['name'] for r in res['results']]
        url = res.get("next")
    return tags

def extract_docker_image(image_tag, out_path):
    console.log(f"Pulling and extracting {image_tag}...")
    subprocess.run(["docker", "pull", image_tag])
    cid = subprocess.check_output(["docker", "create", image_tag]).decode().strip()
    os.makedirs(out_path, exist_ok=True)
    subprocess.run(["docker", "cp", f"{cid}:/", out_path])
    subprocess.run(["docker", "rm", cid])

def run_grype_scan(image_tag, tag):
    report_path = os.path.join("grype_reports", f"{tag}.json")
    os.makedirs("grype_reports", exist_ok=True)
    try:
        subprocess.run([
            "grype", image_tag,
            "--add-cpes-if-none",
            "--output", "json",
            "--file", report_path
        ], check=True)
        with open(report_path) as f:
            report = json.load(f)
        matches = report.get("matches", [])
        if matches:
            criticals = [m for m in matches if m['vulnerability']['severity'].lower() == 'critical']
            fields = [(m['vulnerability']['id'], f"Pkg: `{m['artifact']['name']}`
Ver: `{m['artifact']['version']}`", False) for m in criticals[:5]]
            desc = f"Grype found **{len(matches)} total** vulnerabilities in `{tag}` (Critical: {len(criticals)})."
            send_discord_embed(f"⚠️ CVE Report for `{tag}`", desc, color=0xcc3300, fields=fields)
    except Exception as e:
        console.print(f"[red][-] Grype scan failed on {tag}: {e}[/red]")

def run_docker_history_analysis(image_tag, tag):
    try:
        result = subprocess.run([
            "docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image_tag
        ], capture_output=True, text=True)
        history_path = os.path.join("history_logs", f"{tag}.txt")
        os.makedirs("history_logs", exist_ok=True)
        with open(history_path, 'w') as f:
            f.write(result.stdout)
        if result.stdout:
            send_discord_embed(
                title=f"📝 Docker History for `{tag}`",
                description=f"Saved history log for `{image_tag}` to `history_logs/{tag}.txt`",
                color=0x999999
            )
    except Exception as e:
        console.print(f"[red][-] Docker history failed for {tag}: {e}[/red]")

def run_dive_analysis(image_tag, tag):
    try:
        diff_output = subprocess.run([
            "container-diff", "analyze", image_tag,
            "--type=file", "--json"
        ], capture_output=True, text=True)
        os.makedirs("layer_diff", exist_ok=True)
        report_path = os.path.join("layer_diff", f"{tag}.json")
        with open(report_path, 'w') as f:
            f.write(diff_output.stdout)
        send_discord_embed(
            title=f"🧱 Layer Analysis for `{tag}`",
            description=f"Saved file-level diff report to `layer_diff/{tag}.json`",
            color=0x33cccc
        )
    except Exception as e:
        console.print(f"[red][-] Dive/Container-diff failed for {tag}: {e}[/red]")

def check_github_labels(image_tag, tag):
    try:
        inspect = subprocess.run(["docker", "inspect", image_tag], capture_output=True, text=True)
        data = json.loads(inspect.stdout)[0]
        labels = data.get("Config", {}).get("Labels", {}) or {}
        github_links = [v for k, v in labels.items() if 'github.com' in v]
        if github_links:
            send_discord_embed(
                title=f"🔗 GitHub Metadata in `{tag}`",
                description="Discovered GitHub references in image labels:
" + "
".join(github_links),
                color=0x7289da
            )
    except Exception as e:
        console.print(f"[red][-] Failed to extract GitHub metadata for {tag}: {e}[/red]")

def compare_dirs(old_path, new_path, diff_file):
    with open(diff_file, 'w') as f:
        f.write(f"Diff between {old_path} and {new_path} not implemented.")

def compare_cves(current_tag, previous_tag):
    curr_path = os.path.join("grype_reports", f"{current_tag}.json")
    prev_path = os.path.join("grype_reports", f"{previous_tag}.json")
    try:
        with open(curr_path) as f1, open(prev_path) as f2:
            curr_data = json.load(f1).get("matches", [])
            prev_data = json.load(f2).get("matches", [])
            curr_ids = {m['vulnerability']['id'] for m in curr_data}
            prev_ids = {m['vulnerability']['id'] for m in prev_data}

            new_cves = curr_ids - prev_ids
            fixed_cves = prev_ids - curr_ids

            if new_cves or fixed_cves:
                fields = []
                if new_cves:
                    fields.append(("🆕 New CVEs", '
'.join(list(new_cves)[:5]), False))
                if fixed_cves:
                    fields.append(("✅ Fixed CVEs", '
'.join(list(fixed_cves)[:5]), False))
                send_discord_embed(
                    title=f"🆚 CVE Diff: `{previous_tag}` → `{current_tag}`",
                    description=f"Detected {len(new_cves)} new and {len(fixed_cves)} fixed CVEs.",
                    color=0x3366cc,
                    fields=fields
                )
    except Exception as e:
        console.print(f"[red][-] Failed to compare CVEs: {e}[/red]")

    if os.path.exists(EXTRACT_DIR):
        shutil.rmtree(EXTRACT_DIR)
    os.makedirs(EXTRACT_DIR)

    tags = list_dockerhub_tags()
    prev_tag = None

    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), BarColumn(), TimeElapsedColumn()) as progress:
        task_id = progress.add_task("Starting tag scan...", total=len(tags))
        for tag in tags:
            image_tag = f"{NAMESPACE}/{REPO}:{tag}"
            out_path = os.path.join(EXTRACT_DIR, tag)
            progress.update(task_id, description=f"Scanning {tag}")

            try:
                extract_docker_image(image_tag, out_path)
                scan_extracted_dir(out_path, tag)
                run_semgrep(out_path, tag)
                run_grype_scan(image_tag, tag)
                run_docker_history_analysis(image_tag, tag)
                run_dive_analysis(image_tag, tag)
                check_github_labels(image_tag, tag)
                if prev_tag:
                    prev_path = os.path.join(EXTRACT_DIR, prev_tag)
                    diff_file = f"diff_{prev_tag}_{tag}.txt"
                    compare_dirs(prev_path, out_path, diff_file)
                    compare_cves(tag, prev_tag)
                prev_tag = tag
            except Exception as e:
                console.print(f"[red][-] Error processing {tag}: {e}[/red]")

            progress.advance(task_id)
        progress.update(task_id, description="[green]All tags processed.")

if __name__ == "__main__":
    main()
