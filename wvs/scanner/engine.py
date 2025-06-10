"""
Central scanning engine for WVS.

This module defines the ScannerEngine class, which is responsible for
discovering, loading, and running scanner modules.
"""
import importlib
import os
import pkgutil
from typing import List, Dict, Any, Callable

from wvs.scanner.models import Issue
import wvs.scanner.modules


class ScannerEngine:
    """
    The ScannerEngine discovers, loads, and executes scanner modules.
    """

    def __init__(self, target_url: str):
        """
        Initializes the ScannerEngine with a target URL.

        Args:
            target_url: The base URL to be scanned.
        """
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("Invalid target URL. Must start with http:// or https://")
        self.target_url = target_url
        self.scanner_modules = []

    def _discover_and_load_modules(self) -> List[Callable[[str], Dict[str, Any]]]:
        """
        Discovers and loads scanner modules from the wvs.scanner.modules package.

        Modules are dynamically imported. A module is considered a scanner module
        if it has a 'run(target_url: str) -> Dict[str, Any]' function.

        Returns:
            A list of 'run' functions from the discovered modules.
        """
        loaded_run_functions: List[Callable[[str], Dict[str, Any]]] = []

        # Path to the modules directory
        # Assuming wvs.scanner.modules is a package
        package = wvs.scanner.modules

        for _, modname, ispkg in pkgutil.walk_packages(
                path=package.__path__,
                prefix=package.__name__ + '.',
                onerror=lambda x: None):  # Handle errors during module discovery

            if ispkg:  # Skip __init__.py or sub-packages if any
                continue

            if modname.split('.')[-1].startswith('_'):  # Skip modules starting with an underscore
                continue

            try:
                module = importlib.import_module(modname)
                if hasattr(module, "run") and callable(module.run):
                    loaded_run_functions.append(module.run)
                    self.scanner_modules.append(module)  # Keep track of loaded modules
                    print(f"Successfully loaded module: {modname}")
                else:
                    print(f"Module {modname} does not have a callable 'run' function. Skipping.")
            except ImportError as e:
                print(f"Failed to import module {modname}: {e}")
            except Exception as e:
                print(f"An unexpected error occurred while loading module {modname}: {e}")

        return loaded_run_functions

    def run_scans(self) -> List[Issue]:
        """
        Runs all discovered scanner modules against the target URL.

        Returns:
            A list of Issue objects found by all modules.
        """
        all_issues: List[Issue] = []

        print(f"Discovering and loading scanner modules for target: {self.target_url}...")
        module_run_functions = self._discover_and_load_modules()

        if not module_run_functions:
            print("No scanner modules found or loaded. Exiting.")
            return []

        print(f"\nRunning scans from {len(module_run_functions)} loaded module(s)...")
        for i, run_function in enumerate(module_run_functions):
            module_name = self.scanner_modules[i].__name__ if i < len(self.scanner_modules) else "Unknown Module"
            try:
                print(f"Executing scanner module: {module_name}...")
                # Each run function is expected to return a dict:
                # {"module": "Module Name", "issues": [issue.to_dict(), ...]}
                result_dict = run_function(self.target_url)

                if "issues" in result_dict and isinstance(result_dict["issues"], list):
                    module_issues_data = result_dict["issues"]
                    for issue_data in module_issues_data:
                        try:
                            # Convert dictionary back to Issue object
                            issue_obj = Issue.from_dict(issue_data)
                            all_issues.append(issue_obj)
                        except Exception as e:
                            print(
                                f"Error converting issue data to Issue object in module {module_name}: {e}. Data: {issue_data}")
                else:
                    print(
                        f"Warning: Module {module_name} did not return 'issues' in the expected format. Result: {result_dict}")

            except Exception as e:
                print(f"Error running module {module_name}: {e}")

        print(f"\nFinished running all scans. Total issues found: {len(all_issues)}")
        return all_issues


if __name__ == '__main__':
    # This is for basic testing of the engine.
    # It requires the modules to be runnable from this context.
    print("Starting WVS Scanner Engine (basic test)...")

    # Example: Create dummy modules for testing if they don't exist
    # Ensure wvs/scanner/modules/__init__.py exists
    modules_dir = os.path.join("wvs", "scanner", "modules")
    os.makedirs(modules_dir, exist_ok=True)
    init_file = os.path.join(modules_dir, "__init__.py")
    if not os.path.exists(init_file):
        with open(init_file, "w") as f:
            f.write("# This file makes Python treat the 'modules' directory as a package.\n")

    # Create a dummy module for testing if it doesn't exist
    dummy_module_path = os.path.join(modules_dir, "dummy_scanner.py")
    if not os.path.exists(dummy_module_path):
        with open(dummy_module_path, "w") as f:
            f.write(
                "from wvs.scanner.models import Issue, Severity\n"
                "def run(target_url: str):\n"
                "    print(f'Dummy scanner running on {target_url}')\n"
                "    return {\n"
                "        'module': 'Dummy Scanner',\n"
                "        'issues': [\n"
                "            Issue('DUMMY-001', 'Dummy Issue', 'This is a test issue.', Severity.INFO, 'No remediation.', ['http://example.com']).to_dict()\n"
                "        ]\n"
                "    }\n"
            )

    # Test with a placeholder URL
    # In a real scenario, this URL would be an actual target.
    # The dummy scanner doesn't actually use the URL, so "http://example.com" is fine.
    try:
        engine = ScannerEngine(target_url="http://example.com")
        found_issues = engine.run_scans()
        if found_issues:
            print("\nSample of issues found:")
            for issue in found_issues[:2]:  # Print first 2 issues as sample
                print(f"  ID: {issue.id}, Name: {issue.name}, Severity: {issue.severity.value}")
        else:
            print("No issues found by the scanner engine in this test run.")

    except ValueError as ve:
        print(f"Configuration error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred during the test run: {e}")

    # Clean up dummy module after test (optional)
    # if os.path.exists(dummy_module_path):
    #     os.remove(dummy_module_path)

    print("\nWVS Scanner Engine (basic test) finished.")
