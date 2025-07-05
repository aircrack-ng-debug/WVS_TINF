import typer
from pathlib import Path
import tomli
from typing import Optional, Dict, Any, List  # Added List

from wvs.scanner.engine import ScannerEngine
from wvs.scanner.models import \
    Issue  # Ensure Issue is imported if needed for type hints here, though engine returns them.
from wvs.reporting.console import ConsoleReporter

# Create a Typer application
app = typer.Typer(
    name="wvs",
    help="WVS - Web Vulnerability Scanner: A tool to find common web vulnerabilities.",
    add_completion=False,
)

CONFIG_FILE_NAME = "wvs.toml"
DEFAULT_SCANNER_TIMEOUT = 5

DEFAULT_CONFIG_CONTENT = f"""# Web Vulnerability Scanner (WVS) Configuration

[scanner]
# Timeout for individual web requests in seconds
timeout = {DEFAULT_SCANNER_TIMEOUT}
"""


def load_config(config_path: Path) -> Dict[str, Any]:
    """Loads the WVS configuration from a TOML file."""
    if not config_path.is_file():
        # typer.echo(f"Config file '{config_path}' not found. Using default settings.") # Less verbose
        return {}

    try:
        with open(config_path, "rb") as f:
            config = tomli.load(f)
        return config
    except tomli.TOMLDecodeError as e:
        typer.secho(
            f"Error decoding TOML from '{config_path}': {e}. Using default settings.",
            fg=typer.colors.RED,
            err=True,
        )
        return {}
    except IOError as e:
        typer.secho(
            f"Error reading config file '{config_path}': {e}. Using default settings.",
            fg=typer.colors.RED,
            err=True,
        )
        return {}


@app.command()
def init():
    """
    Initializes WVS by creating a 'wvs.toml' configuration file
    in the current directory.
    """
    config_path = Path(CONFIG_FILE_NAME)
    if config_path.exists():
        typer.secho(
            f"'{CONFIG_FILE_NAME}' already exists in this directory.",
            fg=typer.colors.YELLOW,
        )
        overwrite = typer.confirm("Do you want to overwrite it?", default=False)
        if not overwrite:
            typer.echo("Initialization cancelled.")
            raise typer.Exit()

    try:
        with open(config_path, "w") as f:
            f.write(DEFAULT_CONFIG_CONTENT)
        typer.secho(
            f"'{CONFIG_FILE_NAME}' wurde erfolgreich erstellt.", fg=typer.colors.GREEN
        )
    except IOError as e:
        typer.secho(
            f"Error creating '{CONFIG_FILE_NAME}': {e}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)


@app.command()
def scan(
        target_url: str = typer.Argument(..., help="The target URL to scan, e.g., http://example.com"),
        config_file_path: Path = typer.Option(
            Path(CONFIG_FILE_NAME),
            "--config",
            "-c",
            help="Path to the WVS configuration file (wvs.toml).",
            exists=False,  # Allow it to not exist to use defaults
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output for the report."),
):
    """
    Scans a target URL for web vulnerabilities.
    """
    typer.echo(f"Starting scan for target: {target_url}")

    # Load configuration
    config = load_config(config_file_path)

    scanner_timeout = config.get("scanner", {}).get("timeout", DEFAULT_SCANNER_TIMEOUT)
    if not isinstance(scanner_timeout, int) or scanner_timeout <= 0:
        typer.secho(
            f"Invalid timeout value in config: '{scanner_timeout}'. Using default: {DEFAULT_SCANNER_TIMEOUT}s.",
            fg=typer.colors.YELLOW,
        )
        scanner_timeout = DEFAULT_SCANNER_TIMEOUT

    if config_file_path.is_file():
        typer.echo(f"Using scanner timeout: {scanner_timeout}s (from '{config_file_path.name}')")
    else:
        typer.echo(
            f"Config file '{config_file_path.name}' not found. Using default scanner timeout: {scanner_timeout}s")

    try:
        engine = ScannerEngine(target_url=target_url, timeout=scanner_timeout)
    except ValueError as ve:
        typer.secho(f"Error initializing scanner: {ve}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo("Discovering and running scanner modules...")
    issues: List[Issue] = engine.run_scans()  # Run the scans

    typer.echo(f"Scan complete. Found {len(issues)} potential issue(s).")

    # Initialize ConsoleReporter and display results
    # The ConsoleReporter.print_report is a static method, so no need to instantiate ConsoleReporter if not desired.
    # However, if ConsoleReporter were to have instance state in the future, instantiation would be:
    # reporter = ConsoleReporter(target_url=target_url) # If it took target_url or other params
    # reporter.print_report(issues, verbose=verbose)

    ConsoleReporter.print_report(issues, verbose=verbose)  # Call static method

    if not issues:
        typer.echo(
            "Consider running with --verbose for more details on checks performed, if applicable in future versions.")


if __name__ == "__main__":
    app()
