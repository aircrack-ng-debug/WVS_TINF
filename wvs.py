#!/usr/bin/env python3
"""
WVS - Web Vulnerability Scanner

A simple web vulnerability scanner tool.
"""
import typer
from typing_extensions import Annotated  # For Typer <0.9.0 compatibility if needed, else use typing.Annotated

from wvs.scanner.engine import ScannerEngine
from wvs.reporting.console import ConsoleReporter
from wvs.scanner.models import Issue  # Issue might be needed for type hinting if verbose is used for reporter
import datetime

# Create a Typer application
app = typer.Typer(
    help="WVS - A simple web vulnerability scanner.",
    add_completion=False
)


@app.command()
def scan(
        url: Annotated[str, typer.Option(help="The target URL to scan (e.g., http://example.com).", prompt=False,
                                         rich_help_panel="Required")],
        verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output for the report.")] = False
):
    """
    Scan a target URL for web vulnerabilities.
    """
    if not url:
        typer.echo("Error: URL cannot be empty. Please provide a target URL with --url.", err=True)
        raise typer.Exit(code=1)

    typer.secho(f"[*] Starting WVS scan at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                fg=typer.colors.CYAN)
    typer.secho(f"[*] Target URL: {url}", fg=typer.colors.CYAN)

    try:
        # 1. Create an instance of ScannerEngine
        engine = ScannerEngine(target_url=url)

        # 2. Call engine.run_scans() to get the results
        typer.echo("[*] Running scans...")
        issues = engine.run_scans()  # This will print module loading and execution messages

        # 3. Call ConsoleReporter.print_report() with the results
        if issues:
            typer.secho(f"[*] Scan complete. Found {len(issues)} issue(s). Generating report...",
                        fg=typer.colors.YELLOW)
            ConsoleReporter.print_report(issues, verbose=verbose)
        else:
            typer.secho("[*] Scan complete. No issues found.", fg=typer.colors.GREEN)

    except ValueError as ve:
        typer.secho(f"Configuration Error: {ve}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except ConnectionError as ce:  # More specific error for network issues
        typer.secho(f"Network Error: Could not connect to {url}. Details: {ce}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"An unexpected error occurred: {e}", fg=typer.colors.RED, err=True)
        # Consider logging the full traceback here for debugging if needed
        # import traceback
        # typer.echo(traceback.format_exc(), err=True)
        raise typer.Exit(code=1)
    finally:
        typer.secho(f"[*] WVS scan finished at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    fg=typer.colors.CYAN)


@app.callback()
def callback():
    """
    WVS - Web Vulnerability Scanner.
    Invoke --help for more details.
    """
    # This callback is run before any command.
    # You can use it for global options or setup.
    pass


if __name__ == "__main__":
    app()
