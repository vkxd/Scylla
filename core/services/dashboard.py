"""Dashboard statistics assembled from persisted local intelligence."""
from __future__ import annotations

from .activity import ActivityService
from .evidence import EvidenceService
from .findings import FindingsService, SEVERITIES
from .graph import GraphService


class DashboardService:
    def __init__(self, findings=None, evidence=None, graph=None, activity=None):
        self.findings = findings or FindingsService()
        self.evidence = evidence or EvidenceService()
        self.graph = graph or GraphService()
        self.activity = activity or ActivityService()

    def stats(self) -> dict:
        finding_stats = self.findings.stats()
        return {
            "findings": finding_stats,
            "graph": self.graph.stats(),
            "evidence": self.evidence.count(),
            "activity": self.activity.count(),
        }

    def render(self, modules: int | None = None) -> str:
        stats = self.stats()
        counts = stats["findings"]["by_severity"]
        lines = [
            "╔══════════════════════════════════════════╗",
            "║                 VELTCLI                 ║",
            "╠══════════════════════════════════════════╣",
            "║ FINDINGS                                 ║",
            f"║ Critical: {counts['CRITICAL']:<3} High: {counts['HIGH']:<3} Medium: {counts['MEDIUM']:<3} ║",
            f"║ Low: {counts['LOW']:<3} Info: {counts['INFO']:<3} Total: {stats['findings']['total']:<3} ║",
            "╠══════════════════════════════════════════╣",
            "║ INTELLIGENCE                             ║",
            f"║ Graph Nodes: {stats['graph']['nodes']:<5} Relationships: {stats['graph']['edges']:<5} ║",
            f"║ Evidence Items: {stats['evidence']:<5} Activity Events: {stats['activity']:<5} ║",
            "╠══════════════════════════════════════════╣",
            "║ RECENT ACTIVITY                          ║",
        ]
        recent = self.activity.recent(4)
        if recent:
            lines.extend(f"║ • {event['description'][:36]:<36} ║" for event in recent)
        else:
            lines.append("║ • No activity recorded yet               ║")
        if modules is not None:
            lines.append("╠══════════════════════════════════════════╣")
            lines.append(f"║ Available modules/tools: {modules:<14} ║")
        lines.append("╚══════════════════════════════════════════╝")
        return "\n".join(lines)
