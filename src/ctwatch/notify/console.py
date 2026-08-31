"""Alerts on the terminal, for someone watching the feed."""

from __future__ import annotations

from typing import ClassVar

from rich.console import Console

from ctwatch.notify.base import Alert


class ConsoleNotifier:
    NAME: ClassVar[str] = "console"

    @property
    def name(self) -> str:
        return self.NAME

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    async def publish(self, alert: Alert) -> None:
        shown = alert.domain
        if alert.match.name.is_idn:
            shown = f"{alert.display_name} [dim]({alert.domain})[/dim]"

        colour = "red" if alert.score >= 0.6 else "yellow" if alert.score >= 0.3 else "white"
        self._console.print(
            f"[{colour}]{alert.score:.2f}[/{colour}] {alert.confidence}  "
            f"[bold]{shown}[/bold]  [dim]{alert.match.target.brand}[/dim]"
        )
        self._console.print(f"      {alert.match.detail}")
        if alert.certificate.issuer:
            self._console.print(f"      [dim]issued by {alert.certificate.issuer}[/dim]")

    async def aclose(self) -> None:
        return None
