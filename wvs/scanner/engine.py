"""
Central scanning engine for WVS.

This module defines the ScannerEngine class, which is responsible for
discovering, loading, and running scanner modules.
"""
import importlib
import inspect
import os
import pkgutil
from typing import List

from wvs.scanner.base_module import BaseScannerModule
from wvs.scanner.models import Issue
import wvs.scanner.modules


class ScannerEngine:
    """
    The ScannerEngine discovers, loads, and executes scanner modules.
    """

    def __init__(self, target_url: str, timeout: int = 5):
        """
        Initializes the ScannerEngine with a target URL and timeout.

        Args:
            target_url: The base URL to be scanned.
            timeout: Timeout for network requests in seconds.
        """
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("Invalid target URL. Must start with http:// or https://")
        self.target_url = target_url
        self.timeout = timeout  # Store the timeout
        self.scanner_module_classes: List[type[BaseScannerModule]] = []  # Will store classes now

    def _discover_and_load_modules(self) -> None:
        """
        Discovers and loads scanner module classes from the wvs.scanner.modules package.

        Modules are dynamically imported. A module class is considered a scanner module
        if it is a subclass of BaseScannerModule.
        Populates self.scanner_module_classes.
        """
        self.scanner_module_classes = [] # Reset before discovery
        package = wvs.scanner.modules

        for _, modname, ispkg in pkgutil.walk_packages(
                path=package.__path__,
                prefix=package.__name__ + '.',
                onerror=lambda x: print(f"Error accessing package: {x}") # Log error
            ):

            if ispkg:  # Skip __init__.py or sub-packages if any
                continue

            # Skip modules starting with an underscore (convention for non-public modules)
            # or the base_module itself to avoid self-registration if it's in the same path.
            if modname.split('.')[-1].startswith('_') or modname.endswith('.base_module'):
                continue

            try:
                module = importlib.import_module(modname)
                for _, member_class in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a class defined in the module (not imported)
                    if member_class.__module__ == modname:
                        if issubclass(member_class, BaseScannerModule) and member_class is not BaseScannerModule:
                            if member_class not in self.scanner_module_classes:  # Avoid duplicates
                                self.scanner_module_classes.append(member_class)
                                print(f"Successfully discovered scanner class: {member_class.__name__} from {modname}")
            except ImportError as e:
                print(f"Failed to import module {modname}: {e}")
            except Exception as e: # Catch other potential errors during module inspection
                print(f"An unexpected error occurred while loading/inspecting module {modname}: {e}")


    def run_scans(self) -> List[Issue]:
        """
        Runs all discovered scanner modules against the target URL.

        Returns:
            A list of Issue objects found by all modules.
        """
        all_issues: List[Issue] = []

        print(f"Discovering and loading scanner modules for target: {self.target_url}...")
        self._discover_and_load_modules() # Populates self.scanner_module_classes

        if not self.scanner_module_classes:
            print("No scanner module classes found or loaded. Exiting.")
            return []

        print(f"\nRunning scans from {len(self.scanner_module_classes)} discovered scanner class(es)...")
        for module_class in self.scanner_module_classes:
            try:
                # Instantiate each scanner class, passing self.timeout
                scanner_instance = module_class(timeout=self.timeout)
                module_name = scanner_instance.NAME # Get name from class attribute

                print(f"Executing scanner: {module_name} (class: {module_class.__name__})...")

                # Call scan method, which returns a list of Issue objects
                module_issues = scanner_instance.scan(self.target_url)

                if isinstance(module_issues, list):
                    all_issues.extend(module_issues)
                else:
                    print(f"Warning: Scanner {module_name} did not return a list of Issues. Received: {type(module_issues)}")

            except Exception as e:
                # Use module_class.__name__ if instantiation fails before NAME is accessible
                class_name_for_error = module_class.__name__ if 'module_class' in locals() else "UnknownClass"
                print(f"Error running scanner class {class_name_for_error}: {e}")

        print(f"\nFinished running all scans. Total issues found: {len(all_issues)}")
        return all_issues


if __name__ == '__main__':
    print("Starting WVS Scanner Engine (basic test)...")

    # Test with a placeholder URL.
    # For this test to be meaningful, ensure that actual scanner modules
    # (like A02CryptoScanner, A05ConfigScanner, etc.) are present in
    # wvs/scanner/modules/ and are correctly refactored.
    #
    # You might need to run this from the root of the project for imports to work,
    # e.g., python -m wvs.scanner.engine

    # A publicly accessible, generally well-behaved site for testing header checks, etc.
    # Replace with a local test server if preferred or for more specific tests.
    test_target_url = "https://www.google.com"
    # test_target_url = "http://example.com" # Simpler, less dynamic target

    print(f"Target URL for testing: {test_target_url}")
    print(f"Current working directory: {os.getcwd()}")
    print("Ensure scanner modules are in wvs/scanner/modules/ and compiled (.pyc) if necessary.")
    print("If modules are not found, check PYTHONPATH or run as 'python -m wvs.scanner.engine' from project root.")

    try:
        # Initialize engine with a slightly longer timeout for external sites
        engine = ScannerEngine(target_url=test_target_url, timeout=10)
        found_issues = engine.run_scans()

        if found_issues:
            print(f"\n--- Summary of {len(found_issues)} Issues Found ---")
            for issue in found_issues:
                print(f"  ID: {issue.id:<15} Name: {issue.name:<40} Severity: {issue.severity.value:<8} Module: {issue.id.split('-')[1] if '-' in issue.id else 'N/A'}")
        else:
            print("No issues found by the scanner engine in this test run.")

    except ValueError as ve:
        print(f"Configuration error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred during the test run: {e}")
        import traceback
        traceback.print_exc()


    print("\nWVS Scanner Engine (basic test) finished.")
