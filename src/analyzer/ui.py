"""
Rich UI components for the network traffic analyzer.

Provides colorful, interactive terminal UI elements using rich library.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.tree import Tree
from rich.syntax import Syntax
from rich import box

from analyzer.models import Alert, AlertSeverity, WindowSummary

# Global console instance
console = Console()


class UITheme:
    """Color theme for the UI."""

    # Severity colors
    SEVERITY_COLORS = {
        AlertSeverity.CRITICAL: "bright_red bold",
        AlertSeverity.HIGH: "red",
        AlertSeverity.MEDIUM: "yellow",
        AlertSeverity.LOW: "cyan",
    }

    # Status colors
    SUCCESS = "green"
    ERROR = "red"
    WARNING = "yellow"
    INFO = "cyan"
    MUTED = "dim"

    # Component colors
    HEADER = "bold magenta"
    BORDER = "bright_blue"
    METRIC = "bright_cyan"
    VALUE = "bright_white"


def print_banner():
    """Print application banner."""
    banner = r"""
[bold bright_cyan]
╔════════════════════════════════════════════════════════════════╗
║                                                               ║
║     [bright_magenta]Network Traffic Analyzer[/bright_magenta] ║
║     [dim]Real-time Monitoring & Anomaly Detection[/dim]       ║
║                                                               ║
╚════════════════════════════════════════════════════════════════╝
[/bold bright_cyan]
"""
    console.print(banner)


def print_section_header(title: str, icon: str = ""):
    """Print a section header."""
    if icon:
        title = f"{icon} {title}"
    console.print(f"\n[bold bright_blue]{'═' * 60}[/bold bright_blue]")
    console.print(f"[bold bright_cyan]{title}[/bold bright_cyan]")
    console.print(f"[bold bright_blue]{'═' * 60}[/bold bright_blue]\n")


def create_interfaces_table(interfaces: List[Dict[str, Any]]) -> Table:
    """Create a rich table for network interfaces."""
    table = Table(
        title="🌐 Available Network Interfaces",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        title_style="bold bright_cyan",
    )

    table.add_column("Interface", style="cyan", no_wrap=True)
    table.add_column("IP Address", style="green")
    table.add_column("Status", justify="center")
    table.add_column("Type", style="yellow")

    for iface in interfaces:
        # Determine status color and icon
        status = iface.get("status", "UNKNOWN")
        if status == "UP":
            status_display = "[green]● UP[/green]"
        else:
            status_display = "[red]○ DOWN[/red]"

        table.add_row(
            iface.get("name", "N/A"),
            iface.get("ip", "N/A") or "[dim]No IP[/dim]",
            status_display,
            iface.get("type", "Unknown"),
        )

    return table


def create_window_summary_panel(window: WindowSummary) -> Panel:
    """Create a rich panel for window summary."""
    content = f"""
[bold cyan]Time Range:[/bold cyan] {datetime.fromtimestamp(window.window_start).strftime('%H:%M:%S')} → {datetime.fromtimestamp(window.window_end).strftime('%H:%M:%S')}
[bold cyan]Duration:[/bold cyan] {window.window_end - window.window_start:.1f}s

[bold bright_white]Traffic Volume[/bold bright_white]
  📦 Packets: [bright_cyan]{window.packet_count:,}[/bright_cyan] ([bright_green]{window.packets_per_second:.1f}/s[/bright_green])
  💾 Bytes: [bright_cyan]{_format_bytes(window.byte_count)}[/bright_cyan] ([bright_green]{_format_bytes(window.bytes_per_second)}/s[/bright_green])

[bold bright_white]Network Endpoints[/bold bright_white]
  🔹 Unique Source IPs: [bright_cyan]{window.unique_src_ips}[/bright_cyan]
  🔸 Unique Dest IPs: [bright_cyan]{window.unique_dst_ips}[/bright_cyan]

[bold bright_white]Protocol Distribution[/bold bright_white]
{_format_protocol_distribution(window.protocol_counts)}

[bold bright_white]TCP Flags[/bold bright_white]
  SYN: [cyan]{window.syn_count}[/cyan]  ACK: [cyan]{window.ack_count}[/cyan]  RST: [cyan]{window.rst_count}[/cyan]

[bold bright_white]Entropy[/bold bright_white]
  🎲 Destination IP Entropy: [bright_cyan]{window.dst_ip_entropy:.2f}[/bright_cyan]
"""
    return Panel(
        content.strip(),
        title="📊 Window Summary",
        border_style="bright_blue",
        box=box.DOUBLE,
    )


def create_alert_panel(alert: Alert) -> Panel:
    """Create a rich panel for an alert."""
    severity_color = UITheme.SEVERITY_COLORS.get(alert.severity, "white")

    # Severity badge
    severity_badge = f"[{severity_color}]● {alert.severity.value.upper()}[/{severity_color}]"

    # Evidence formatting
    evidence_lines = []
    for key, value in alert.evidence.items():
        evidence_lines.append(f"  • [cyan]{key}[/cyan]: [bright_white]{value}[/bright_white]")

    content = f"""
{severity_badge}

[bold cyan]Detector:[/bold cyan] {alert.detector}
[bold cyan]Category:[/bold cyan] {alert.category}
[bold cyan]Time:[/bold cyan] {datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')}

[bold bright_white]Summary[/bold bright_white]
{alert.summary}

[bold bright_white]Evidence[/bold bright_white]
{chr(10).join(evidence_lines)}

[bold bright_white]Interpretation[/bold bright_white]
{alert.interpretation or '[dim]No interpretation available[/dim]'}
"""

    return Panel(
        content.strip(),
        title=f"⚠️  Alert: {alert.alert_id}",
        border_style=severity_color,
        box=box.DOUBLE,
    )


def create_session_info_panel(
    session_id: str,
    mode: str,
    interface: str,
    window_size: int,
    detectors: List[str],
) -> Panel:
    """Create a panel showing session information."""
    detector_list = "\n".join([f"  • [cyan]{d}[/cyan]" for d in detectors])

    content = f"""
[bold cyan]Session ID:[/bold cyan] [bright_white]{session_id}[/bright_white]
[bold cyan]Mode:[/bold cyan] [bright_green]{mode}[/bright_green]
[bold cyan]Interface:[/bold cyan] [bright_cyan]{interface}[/bright_cyan]
[bold cyan]Window Size:[/bold cyan] [bright_magenta]{window_size}s[/bright_magenta]

[bold bright_white]Active Detectors[/bold bright_white]
{detector_list}
"""

    return Panel(
        content.strip(),
        title="🔍 Session Configuration",
        border_style="bright_blue",
        box=box.ROUNDED,
    )


def create_statistics_table(stats: Dict[str, Any]) -> Table:
    """Create a statistics table."""
    table = Table(
        title="📈 Session Statistics",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
    )

    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="bright_white", justify="right")

    for key, value in stats.items():
        # Format the key nicely
        formatted_key = key.replace("_", " ").title()
        # Format the value
        if isinstance(value, float):
            formatted_value = f"{value:.2f}"
        elif isinstance(value, int):
            formatted_value = f"{value:,}"
        else:
            formatted_value = str(value)

        table.add_row(formatted_key, formatted_value)

    return table


def create_top_talkers_table(top_talkers: List[Dict[str, Any]], limit: int = 10) -> Table:
    """Create a table showing top talkers."""
    table = Table(
        title=f"👥 Top {limit} Talkers",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
    )

    table.add_column("Rank", style="dim", width=6, justify="center")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Packets", style="bright_green", justify="right")
    table.add_column("Bytes", style="bright_yellow", justify="right")
    table.add_column("% of Total", style="bright_magenta", justify="right")

    for idx, talker in enumerate(top_talkers[:limit], 1):
        rank_style = "bold bright_cyan" if idx <= 3 else "dim"
        table.add_row(
            f"[{rank_style}]#{idx}[/{rank_style}]",
            talker.get("ip", "N/A"),
            f"{talker.get('packets', 0):,}",
            _format_bytes(talker.get("bytes", 0)),
            f"{talker.get('percentage', 0):.1f}%",
        )

    return table


def print_success(message: str):
    """Print a success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str):
    """Print an error message."""
    console.print(f"[red]✗[/red] {message}", style="red")


def print_warning(message: str):
    """Print a warning message."""
    console.print(f"[yellow]⚠[/yellow] {message}", style="yellow")


def print_info(message: str):
    """Print an info message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")


def create_progress_bar(description: str = "Processing...") -> Progress:
    """Create a progress bar."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


def create_baseline_tree(baseline_data: Dict[str, Any]) -> Tree:
    """Create a tree view of baseline data."""
    tree = Tree("📊 Baseline Statistics", style="bold bright_cyan")

    # Traffic metrics
    traffic_node = tree.add("🚦 Traffic Metrics", style="cyan")
    traffic_node.add(f"Mean PPS: [bright_white]{baseline_data.get('mean_pps', 0):.2f}[/bright_white]")
    traffic_node.add(f"Mean BPS: [bright_white]{_format_bytes(baseline_data.get('mean_bps', 0))}/s[/bright_white]")
    traffic_node.add(f"Packet Size: [bright_white]{baseline_data.get('mean_packet_size', 0):.2f} bytes[/bright_white]")

    # Protocol distribution
    proto_dist = baseline_data.get("protocol_distribution", {})
    if proto_dist:
        proto_node = tree.add("📡 Protocol Distribution", style="cyan")
        for proto, count in proto_dist.items():
            proto_node.add(f"{proto}: [bright_white]{count}[/bright_white]")

    # TCP metrics
    tcp_node = tree.add("🔌 TCP Metrics", style="cyan")
    tcp_node.add(f"Mean SYN Count: [bright_white]{baseline_data.get('mean_syn_count', 0):.2f}[/bright_white]")
    tcp_node.add(f"Mean ACK Count: [bright_white]{baseline_data.get('mean_ack_count', 0):.2f}[/bright_white]")

    # Entropy
    entropy_node = tree.add("🎲 Entropy", style="cyan")
    entropy_node.add(
        f"Dst IP Entropy: [bright_white]{baseline_data.get('mean_dst_ip_entropy', 0):.2f}[/bright_white]"
    )

    return tree


def _format_bytes(num_bytes: float) -> str:
    """Format bytes in human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _format_protocol_distribution(protocol_counts: Dict[str, int]) -> str:
    """Format protocol distribution with bars."""
    if not protocol_counts:
        return "[dim]No protocols detected[/dim]"

    total = sum(protocol_counts.values())
    lines = []

    for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total) * 100
        bar_length = int(percentage / 2)  # Scale to fit
        bar = "█" * bar_length
        lines.append(f"  {proto:8s} [{count:6,}] [cyan]{bar}[/cyan] {percentage:5.1f}%")

    return "\n".join(lines)


def confirm(message: str, default: bool = True) -> bool:
    """Ask for user confirmation."""
    from prompt_toolkit import prompt
    from prompt_toolkit.validation import Validator, ValidationError

    class YesNoValidator(Validator):
        def validate(self, document):
            text = document.text.lower()
            if text and text not in ["y", "n", "yes", "no"]:
                raise ValidationError(message="Please enter y/n or yes/no")

    default_text = "Y/n" if default else "y/N"
    try:
        result = prompt(
            f"{message} [{default_text}]: ",
            validator=YesNoValidator(),
            default="" if default else "n",
        )
        if not result:
            return default
        return result.lower() in ["y", "yes"]
    except (KeyboardInterrupt, EOFError):
        return False


def select_from_list(items: List[str], message: str = "Select an option") -> Optional[str]:
    """Interactive selection from a list."""
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter

    completer = WordCompleter(items, ignore_case=True)

    console.print(f"\n[cyan]{message}:[/cyan]")
    for idx, item in enumerate(items, 1):
        console.print(f"  [dim]{idx}.[/dim] [bright_white]{item}[/bright_white]")

    try:
        result = prompt(
            "\nEnter number or name: ",
            completer=completer,
        )

        # Try to parse as index
        if result.isdigit():
            idx = int(result) - 1
            if 0 <= idx < len(items):
                return items[idx]

        # Try to match name
        if result in items:
            return result

        # Try case-insensitive match
        for item in items:
            if item.lower() == result.lower():
                return item

        print_error("Invalid selection")
        return None

    except (KeyboardInterrupt, EOFError):
        return None
