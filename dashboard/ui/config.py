"""
Configuration settings for the ATTESTOR dashboard.
"""

APP_NAME = "ATTESTOR"
APP_VERSION = "1.0.0"

SUPPORTED_PLATFORMS = [
    "Windows",
    "Linux"
]

RESULT_STATUSES = [
    "Pass",
    "Fail",
    "Error"
]

DEFAULT_REPORT_TITLE = "ATTESTOR Security Audit Report"

DEFAULT_DATA_FILE = "sample_data.json"
DEFAULT_REPORT_FILE = "sample_report.json"
DEFAULT_UI_CONFIG = "ui_config.yaml"
