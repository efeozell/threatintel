import sys
import os
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import validate_config, WEB_HOST, WEB_PORT
from core.validator import validate_target
from core.query_manager import run_queries
from output.cli_output import print_result, console

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="🛡️  Threat Intelligence Tool — Queries IP, Domain and Hash",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
    Examples:
    python main.py --ip 1.2.3.4
    python main.py --domain evil.com
    python main.py --hash 44d88612fea8a8f36de82e1278abb02f
    python main.py --ip 1.2.3.4 --save
    python main.py --web
        """
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ip", metavar="IP", help="Query IP Address")
    group.add_argument("--domain", metavar="DOMAIN", help="Query Domain")
    group.add_argument("--hash", metavar="HASH", help="Query file hash")
    group.add_argument("--web", action="store_true", help="Start web dashboard")

    parser.add_argument(
        "--save",
        action="store_true",
        help="Save results to JSON"
    )

    return parser.parse_args()

def run_cli(target, save=False):
    validation = validate_target(target)

    if not validation["valid"]:
        console.print(f"[red]❌ Invalid input: {validation['error']}[/red]")
        sys.exit(1)

    cleaned_target = validation["target"]
    target_type = validation["type"]

    console.print(f"\n[cyan] 🔍 Querying: {cleaned_target} ({target_type.upper()})")
    console.print("[cyan]⏳ API's querying...[/cyan]\n")

    result = run_queries(cleaned_target, target_type)

    print_result(result)

    if save:
        from output.report import save_json_report
        filepath = save_json_report(result)
        console.print(f"[green]💾 Rapor saved: {filepath}[/green]\n")

    return result


def run_web():
    from web.app import create_app
    console.print(f"\n[cyan]🌐 Web dashboard starting...[/cyan]")
    console.print(f"[cyan]📡 Address: http://{WEB_HOST}:{WEB_PORT}[/cyan]")
    console.print("[yellow]To stop CTRL+C[/yellow]\n")

    app = create_app()
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)

def main():
    try:
        validate_config()
    except ValueError as e:
        print(f"❌ Configuration error: {e}")
        sys.exit(1)

    args = parse_arguments()

    if not any([args.ip, args.domain, args.hash, args.web]):
        print("❌ Parameter need. For use: python main.py --help")
        sys.exit(1)

    if args.web:
        run_web()
        return

    target = args.ip or args.domain or args.hash
    run_cli(target, save=args.save)

if __name__ == "__main__":
    main()

