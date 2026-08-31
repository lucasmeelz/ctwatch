"""Alerts posted to an endpoint the operator declared.

The destination goes through the same host allowlist as everything else. An
operator enabling a webhook is declaring that host, exactly the way they
declare a source; it is never inferred from anything observed.
"""

from __future__ import annotations

from typing import ClassVar

from ctwatch.net.client import NetworkPolicyError, PassiveHttpClient, UpstreamError
from ctwatch.notify.base import Alert


class WebhookNotifier:
    NAME: ClassVar[str] = "webhook"

    @property
    def name(self) -> str:
        return self.NAME

    def __init__(
        self,
        *,
        http: PassiveHttpClient,
        url: str,
        min_score: float = 0.0,
    ) -> None:
        self._http = http
        self._url = url
        self._min_score = min_score
        self._errors: list[str] = []

    @property
    def errors(self) -> list[str]:
        return list(self._errors)

    async def publish(self, alert: Alert) -> None:
        if alert.score < self._min_score:
            return
        try:
            await self._http.post_json(self._url, payload=alert.as_dict())
        except (UpstreamError, NetworkPolicyError) as exc:
            # A monitor must not die because a chat integration is down.
            self._errors.append(f"{type(exc).__name__}: {exc}")

    async def aclose(self) -> None:
        return None
