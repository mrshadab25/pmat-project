"""
utils/display.py — Terminal display helpers for PMAT
"""


class Colors:
    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


SEV_COLOR = {
    "critical": Colors.RED + Colors.BOLD,
    "high":     Colors.ORANGE + Colors.BOLD,
    "medium":   Colors.YELLOW,
    "low":      Colors.BLUE,
    "info":     Colors.CYAN,
    "clean":    Colors.GREEN,
}

SEV_LABEL = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]    ",
    "medium":   "[MEDIUM]  ",
    "low":      "[LOW]     ",
    "info":     "[INFO]    ",
    "clean":    "[CLEAN]   ",
}


class Banner:
    @staticmethod
    def section(step: str, title: str):
        print(f"\n{Colors.BOLD}{Colors.CYAN}  ┌─ {step}: {title} {'─'*max(1,50-len(step)-len(title))}┐{Colors.RESET}")


def print_section(step: str, title: str, silent: bool = False):
    if not silent:
        print(f"\n{Colors.BOLD}{Colors.BLUE}  ┌─ {step}: {title}{Colors.RESET}")
        print(f"{Colors.GRAY}  {'─'*60}{Colors.RESET}")


def print_finding(label: str, message: str, severity: str = "info", silent: bool = False):
    if silent:
        return
    color = SEV_COLOR.get(severity, Colors.WHITE)
    sev_tag = SEV_LABEL.get(severity, f"[{severity.upper():8s}]")
    print(f"  {color}{sev_tag}{Colors.RESET}  {message}")
