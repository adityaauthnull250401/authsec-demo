"""Sandbox-only issue operations using the personal demo App."""

from __future__ import annotations

from typing import Any

from apps.mcp_server.github.client import GitHubInstallationClient

DEMO_LABEL = "authsec-demo"
CLEANED_LABEL = "authsec-demo-cleaned"


class GitHubIssueWriter:
    def __init__(self, client: GitHubInstallationClient, repository: str) -> None:
        self._client = client
        self._repository = repository

    async def create_issue(self, title: str, body: str, run_id: str) -> dict[str, Any]:
        await self._ensure_label(DEMO_LABEL, "1d76db", "Created by the AuthSec demo")
        marker = f"<!-- authsec-demo-run:{run_id} -->"
        response = await self._client.request(
            "POST",
            f"/repos/{self._repository}/issues",
            json={"title": title, "body": f"{body}\n\n{marker}", "labels": [DEMO_LABEL]},
            expected={201},
        )
        issue = response.json()
        return {
            "number": issue["number"],
            "title": issue["title"],
            "state": issue["state"],
            "url": issue["html_url"],
            "run_id": run_id,
        }

    async def close_run_issues(self, run_id: str) -> list[int]:
        """Close only sandbox issues bearing this demo run's exact body marker."""

        await self._ensure_label(CLEANED_LABEL, "6e7781", "Closed by AuthSec demo reset")
        response = await self._client.request(
            "GET",
            f"/repos/{self._repository}/issues",
            params={"state": "all", "labels": DEMO_LABEL, "per_page": 100},
        )
        marker = f"<!-- authsec-demo-run:{run_id} -->"
        closed: list[int] = []
        for issue in response.json():
            if "pull_request" in issue or marker not in str(issue.get("body") or ""):
                continue
            number = int(issue["number"])
            await self._client.request(
                "PATCH",
                f"/repos/{self._repository}/issues/{number}",
                json={"state": "closed", "labels": [DEMO_LABEL, CLEANED_LABEL]},
            )
            closed.append(number)
        return closed

    async def _ensure_label(self, name: str, color: str, description: str) -> None:
        existing = await self._client.request(
            "GET",
            f"/repos/{self._repository}/labels/{name}",
            expected={200, 404},
        )
        if existing.status_code == 200:
            return
        await self._client.request(
            "POST",
            f"/repos/{self._repository}/labels",
            json={"name": name, "color": color, "description": description},
            expected={201, 422},
        )
