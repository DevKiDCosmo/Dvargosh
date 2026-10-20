#!/usr/bin/env python3
"""
Dvargosh Terminal UI Library
Provides rich, colorized terminal output with box panels, status badges,
progress indicators, and interactive prompt selection.
Automatically utilizes 'rich' if available, otherwise falls back gracefully
to high-fidelity ANSI terminal styling.
"""

import sys
import shutil

# Try importing rich
try:
    import rich
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    _HAS_RICH = True
    _console = Console()
except ImportError:
    _HAS_RICH = False
    _console = None

# ANSI Escape Sequences for Fallback
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_BLUE = "\033[44m"

def print_banner(title: str, subtitle: str = ""):
    """Prints a styled full-width banner."""
    if _HAS_RICH:
        content = f"[bold cyan]{title}[/bold cyan]"
        if subtitle:
            content += f"\n[dim]{subtitle}[/dim]"
        _console.print(Panel(content, border_style="blue", expand=True))
    else:
        width = min(shutil.get_terminal_size((80, 20)).columns, 80)
        print(f"\n{BOLD}{BLUE}{'=' * width}{RESET}")
        print(f"{BOLD}{CYAN}{title.center(width)}{RESET}")
        if subtitle:
            print(f"{DIM}{subtitle.center(width)}{RESET}")
        print(f"{BOLD}{BLUE}{'=' * width}{RESET}\n")

def print_step(step_num: int, total_steps: int, title: str):
    """Prints a pipeline step progress indicator."""
    if _HAS_RICH:
        _console.print(f"\n[bold blue][{step_num}/{total_steps}][/bold blue] [bold white]{title}[/bold white]")
    else:
        print(f"\n{BOLD}{BLUE}[{step_num}/{total_steps}]{RESET} {BOLD}{WHITE}{title}{RESET}")

def print_success(msg: str):
    """Prints a success message."""
    if _HAS_RICH:
        _console.print(f"  [bold green]✓[/bold green] {msg}")
    else:
        print(f"  {BOLD}{GREEN}✓{RESET} {msg}")

def print_info(msg: str):
    """Prints an informational message."""
    if _HAS_RICH:
        _console.print(f"  [bold cyan]ℹ[/bold cyan] {msg}")
    else:
        print(f"  {BOLD}{CYAN}ℹ{RESET} {msg}")

def print_warn(msg: str):
    """Prints a warning message."""
    if _HAS_RICH:
        _console.print(f"  [bold yellow]⚠ {msg}[/bold yellow]")
    else:
        print(f"  {BOLD}{YELLOW}⚠ {msg}{RESET}")

def print_error(msg: str):
    """Prints an error message."""
    if _HAS_RICH:
        _console.print(f"  [bold red]✗ {msg}[/bold red]")
    else:
        print(f"  {BOLD}{RED}✗ {msg}{RESET}", file=sys.stderr)

def print_table(title: str, headers: list, rows: list):
    """Prints a formatted ASCII or Rich table."""
    if _HAS_RICH:
        table = Table(title=title, border_style="cyan")
        for h in headers:
            table.add_column(h, style="white", header_style="bold cyan")
        for row in rows:
            table.add_row(*[str(col) for col in row])
        _console.print(table)
    else:
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, col in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(col)))

        total_width = sum(col_widths) + len(headers) * 3 + 1
        sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
        header_row = "| " + " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers)) + " |"

        print(f"\n{BOLD}{title}{RESET}")
        print(sep)
        print(f"{BOLD}{CYAN}{header_row}{RESET}")
        print(sep)
        for row in rows:
            formatted = "| " + " | ".join(f"{str(col):<{col_widths[i]}}" for i, col in enumerate(row)) + " |"
            print(formatted)
        print(sep + "\n")

def prompt_choice(prompt: str, choices: list, default: str = None) -> str:
    """Prompts the user to select an option from a list of choices."""
    if _HAS_RICH:
        return Prompt.ask(prompt, choices=choices, default=default)
    else:
        choices_str = "/".join(choices)
        def_str = f" [{default}]" if default else ""
        while True:
            val = input(f"{BOLD}{prompt}{RESET} ({choices_str}){def_str}: ").strip()
            if not val and default:
                return default
            if val in choices:
                return val
            print(f"{RED}Invalid selection. Options: {', '.join(choices)}{RESET}")

def prompt_text(prompt: str, default: str = "") -> str:
    """Prompts the user for a text input."""
    if _HAS_RICH:
        return Prompt.ask(prompt, default=default)
    else:
        def_str = f" [{default}]" if default else ""
        val = input(f"{BOLD}{prompt}{RESET}{def_str}: ").strip()
        return val if val else default
