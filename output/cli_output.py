import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box
from datetime import datetime

console = Console()

def get_score_color(score):
    if score <= 30:
        return "green"
    elif score <= 60:
        return "yellow"
    elif score <= 80:
        return "dark_orange"
    else:
        return "red"

def print_header(target, target_type):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Type:[/bold]   {target_type.upper()}\n"
        f"[bold]Date:[/bold]   {now}"
    )
    console.print(Panel(
        content,
        title="[bold cyan]🛡️  Threat Intelligence Report[/bold cyan]",
        border_style="cyan"
    ))


def print_threat_score(result):
    score = result["final_score"]
    threat = result["threat_level"]
    color = get_score_color(score)

    content = (
        f"[bold {color}]{threat['emoji']} {threat['level']}[/bold {color}]\n"
        f"[bold]Score: [{color}]{score}/100[/{color}][/bold]"
    )
    console.print(Panel(content, title="[bold]THREAT SCORE[/bold]", border_style=color, expand=False))

def print_virustotal(vt_result):
    if not vt_result:
        return

    if vt_result.get("error"):
        console.print(Panel(
            f"[red]❌ Error: {vt_result['error']}[/red]",
            title="[bold green]VirusTotal[/bold green]",
            border_style="green"
        ))
        return

    if vt_result.get("skipped"):
        console.print(Panel(
            f"[yellow] Skipped: {vt_result.get('reason', '')}[/yellow]",
            title="[bold green]VirusTotal[/bold green]",
            border_style="green"
        ))
        return

    stats = vt_result.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = stats.get("total_engines", 0)

    mal_color = "red" if malicious > 0 else "green"
    sus_color = "yellow" if suspicious > 0 else "green"

    lines = [
        f"[{mal_color}]Malicious  : {malicious}/{total} engine[/{mal_color}]",
        f"[{sus_color}]Suspicious : {suspicious}/{total} engine[/{sus_color}]",
        f"Harmless   : {stats.get('harmless', 0)}/{total} engine",
    ]

    if vt_result.get("target_type") == "ip":
        lines.append(f"Country    : {vt_result.get('country', 'N/A')}")
        lines.append(f"Owner      : {vt_result.get('owner', 'N/A')}")
        lines.append(f"ASN        : {vt_result.get('asn', 'N/A')}")

    if vt_result.get("target_type") == "domain":
        lines.append(f"Registrar  : {vt_result.get('registrar', 'N/A')}")

    if vt_result.get("target_type") == "hash":
        lines.append(f"File Name  : {vt_result.get('file_name', 'N/A')}")
        lines.append(f"File Type  : {vt_result.get('file_type', 'N/A')}")
        size = vt_result.get("file_size", 0)
        lines.append(f"File Size  : {size:,} bytes")

    console.print(Panel(
        "\n".join(lines),
        title="[bold green]VirusTotal[/bold green]",
        border_style="green"
    ))

def print_abuseipdb(abuse_result):
    if not abuse_result:
        return

    if abuse_result.get("error"):
        console.print(Panel(
            f"[red]❌ Error: {abuse_result['error']}[/red]",
            title="[bold blue]AbuseIPDB[/bold blue]",
            border_style="blue"
        ))
        return

    if abuse_result.get("skipped"):
        console.print(Panel(
            f"[yellow]⏭ Skipped: {abuse_result.get('reason', '')}[/yellow]",
            title="[bold blue]AbuseIPDB[/bold blue]",
            border_style="blue"
        ))
        return

    abuse_score = abuse_result.get("abuse_score", 0)
    score_color = get_score_color(abuse_score)

    tor_status = "[red]✓ Tor Exit Node[/red]" if abuse_result.get("is_tor") else "[green]✗ Not Tor[/green]"
    whitelist = "[green]✓ Whitelisted[/green]" if abuse_result.get("is_whitelisted") else "[yellow]✗ Not Whitelisted[/yellow]"

    lines = [
        f"Abuse Score   : [{score_color}]{abuse_score}/100[/{score_color}]",
        f"Total Reports : {abuse_result.get('total_reports', 0)}",
        f"Last Reported : {abuse_result.get('last_reported', 'N/A')}",
        f"Country       : {abuse_result.get('country', 'N/A')}",
        f"ISP           : {abuse_result.get('isp', 'N/A')}",
        f"Usage Type    : {abuse_result.get('usage_type', 'N/A')}",
        f"Tor Node      : {tor_status}",
        f"Whitelisted   : {whitelist}"
    ]

    console.print(Panel(
        "\n".join(lines),
        title="[bold blue]AbuseIPDB[/bold blue]",
        border_style="blue"
    ))

def print_shodan(shodan_result):
    if not shodan_result:
        return

    if shodan_result.get("error"):
        console.print(Panel(
            f"[red]❌ Error: {shodan_result['error']}[/red]",
            title="[bold magenta]Shodan[/bold magenta]",
            border_style="magenta"
        ))
        return

    if shodan_result.get("skipped"):
        console.print(Panel(
            f"[yellow]⏭ Skipped: {shodan_result.get('reason', '')}[/yellow]",
            title="[bold magenta]Shodan[/bold magenta]",
            border_style="magenta"
        ))
        return

    if not shodan_result.get("found"):
        console.print(Panel(
            "[yellow]This IP address is not registered on Shodan[/yellow]",
            title="[bold magenta]Shodan[/bold magenta]",
            border_style="magenta"
        ))
        return

    ports = shodan_result.get("open_ports", [])
    ports_str = ", ".join(map(str, ports)) if ports else "Not"

    critical = shodan_result.get("critical_ports", [])
    critical_str = f"[red]{', '.join(map(str, critical))}[/red]" if critical else "[green]Not[/green]"

    vulns = shodan_result.get("vulns", [])
    vulns_str = f"[red]{', '.join(vulns)}[/red]" if vulns else "[green]Not[/green]"

    lines = [
        f"Organisation  : {shodan_result.get('org', 'N/A')}",
        f"Country       : {shodan_result.get('country', 'N/A')}",
        f"City          : {shodan_result.get('city', 'N/A')}",
        f"OS            : {shodan_result.get('os', 'N/A')}",
        f"Open Ports    : {ports_str}",
        f"Critical Ports: {critical_str}",
        f"CVEs          : {vulns_str}",
    ]

    services = shodan_result.get("services", [])
    if services:
        lines.append("\nServices:")
        for svc in services:
            product = svc.get("product", "")
            version = svc.get("version", "")
            info = f"{product} {version}".strip() or "Unknown"
            lines.append(f"  → {svc['port']}/{svc['transport']} — {info}")

    console.print(Panel(
        "\n".join(lines),
        title="[bold magenta]Shodan[/bold magenta]",
        border_style="magenta"
    ))

def print_findings(findings):
    if not findings:
        return

    lines = [f"• {f}" for f in findings]
    console.print(Panel(
        "\n".join(lines),
        title="[bold yellow]Key Findings[/bold yellow]",
        border_style="yellow"
    ))

def print_result(result):
    console.print()
    print_header(result["target"], result["target_type"])
    print_threat_score(result)

    raw = result.get("raw", {})
    print_virustotal(raw.get("virustotal"))
    print_abuseipdb(raw.get("abuseipdb"))
    print_shodan(raw.get("shodan"))
    print_findings(result.get("findings"))
    console.print()


if __name__ == "__main__":
    # Test — sahte veri
    from core.query_manager import run_queries
    result = run_queries("185.220.101.1", "ip")
    print_result(result)

