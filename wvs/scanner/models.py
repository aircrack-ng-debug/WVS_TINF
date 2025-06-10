"""
This module defines data models used in the WVS scanner.
"""
from dataclasses import dataclass
from enum import Enum

# It's good practice to define Enums and other shared data structures
# that might be used by models in the same file or a dedicated types file.

class Severity(Enum):
    """Represents the severity of a vulnerability."""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class Issue:
    """
    Represents a security issue found by a scanner module.
    """
    id: str
    name: str
    description: str
    severity: Severity
    remediation: str
    references: list[str]
    cvss_vector: str = ""
    cvss_score: float = 0.0

    def __post_init__(self):
        if not isinstance(self.severity, Severity):
            # Attempt to convert from string if severity is not already a Severity enum
            try:
                self.severity = Severity[self.severity.upper()]
            except KeyError:
                raise ValueError(
                    f"Invalid severity value: {self.severity}. "
                    f"Must be one of {', '.join([s.name for s in Severity])}"
                )
        if not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")

    def to_dict(self):
        """Converts the Issue object to a dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value, # Store enum value
            "remediation": self.remediation,
            "references": self.references,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
        }

    @classmethod
    def from_dict(cls, data: dict):
        """Creates an Issue object from a dictionary."""
        # Convert severity string back to Enum member
        severity_str = data.get("severity", "INFO") # Default to INFO if missing
        try:
            severity = Severity[severity_str.upper()]
        except KeyError:
            # Handle cases where severity might be stored as "Info" instead of "INFO"
            severity = Severity(severity_str)


        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            severity=severity,
            remediation=data["remediation"],
            references=data.get("references", []),
            cvss_vector=data.get("cvss_vector", ""),
            cvss_score=data.get("cvss_score", 0.0),
        )
