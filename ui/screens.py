import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from rich.text import Text
from textual.widgets import Button, Footer, Header, Input, RichLog, Static


ASCII_ART = """\
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄     ▄▄▄     ▄▄▄▄▄▄
█       █       █  █ █  █   █   █   █   █      █
█  ▄▄▄▄▄█       █  █▄█  █   █   █   █   █  ▄   █
█ █▄▄▄▄▄█     ▄▄█     █   █   █   █   █ █▄█  █
█▄▄▄▄▄  █     █ █▄     ▄█   █▄▄▄█   █▄▄▄█      █
 ▄▄▄▄▄█ █     █▄▄  █   █ █       █       █  ▄   █
█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄█ █▄▄█
"""


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    description: str
    module_id: str
    fields: List[Tuple[str, str, str]] = field(default_factory=list)
    what_it_does: str = "Runs a public-information check for the selected target."
    why_it_matters: str = "It helps you understand what is exposed and what should be reviewed."


@dataclass(frozen=True)
class CategorySpec:
    key: str
    name: str
    description: str
    tools: List[ToolSpec]


CATEGORIES = [
    CategorySpec(
        "vulnerability",
        "VULNERABILITY",
        "Surface mapping, CVE correlation, and exposed asset checks.",
        [
            ToolSpec("ports", "Open Ports", "TCP/UDP service and risk analysis.", "sub_ports", [("target", "Target", "example.com")], "Checks which network doors (ports) respond on a host and what services they may expose.", "Open ports reveal reachable services; closing unnecessary ones reduces attack surface."),
            ToolSpec("ddos-assessment", "DDoS Resilience Assessment", "Safely identify resilience gaps and recommended fixes.", "sub_ddos_assessment", [("target", "Website URL", "https://example.com")], "Looks for public signs of CDN/WAF, rate limiting, caching, and other traffic protections without attacking the site.", "DDoS means distributed denial of service; this helps website owners find protection gaps before real traffic spikes occur."),
            ToolSpec("subdomains", "Subdomains / Pages", "Discover public subdomains and common public paths.", "sub_subdomains", [("target", "Domain", "example.com")], "Finds related names such as dev.example.com and other publicly visible website locations.", "Forgotten test sites and admin pages can expose software, data, or login panels."),
            ToolSpec("tech", "Tech Stack", "Fingerprint headers, TLS, and CMS signals.", "sub_tech", [("target", "Target", "https://example.com")], "Identifies public clues about software such as a web server, framework, CMS, or TLS setup.", "Knowing the technology helps you patch old versions and configure the right defenses."),
            ToolSpec("cves", "CVE Matching", "Match detected versions to known CVEs.", "sub_cves", [("target", "Target", "example.com")], "Matches known software versions to CVEs, which are public records of specific security vulnerabilities.", "CVE matches tell you which patches or upgrades should be prioritized; a match is a lead to verify, not automatic proof of compromise."),
            ToolSpec("buckets", "Cloud Buckets", "Check for public cloud storage exposure.", "sub_buckets", [("target", "Organization or domain", "example.com")], "Looks for publicly reachable cloud-storage naming patterns such as S3 or Blob containers.", "A misconfigured bucket can accidentally expose files, backups, or customer data."),
        ],
    ),
    CategorySpec(
        "social",
        "SOCIAL",
        "Username reconnaissance and public identity correlation.",
        [ToolSpec("username-checker", "Username Reconnaissance", "Search public platform profiles.", "sub_sherlock", [("username", "Username", "vkxd")], "Searches public websites for profiles using the same username, similar to Sherlock.", "It shows where a public alias may be reused; only public profile results are checked." )],
    ),
    CategorySpec(
        "web",
        "WEB",
        "Website ownership, hosting, and DNS intelligence.",
        [ToolSpec("info", "Website Information", "Build a unified domain overview.", "web_info", [("target", "Domain", "example.com")], "Collects a basic public overview of a domain, including hosting, ownership clues, and DNS records.", "It gives you a starting map of how a website is connected to the internet." )],
    ),
    CategorySpec(
        "temps",
        "TEMPS",
        "Disposable mailbox utilities.",
        [ToolSpec("tempmail", "Temporary Mail", "Generate a disposable inbox.", "run_all", [], "Creates a temporary mailbox through the configured disposable-mail provider.", "A temporary inbox can reduce spam when signing up for a low-trust service; never use it for important accounts." )],
    ),
    CategorySpec(
        "dns",
        "DNS",
        "Passive infrastructure and certificate mapping.",
        [ToolSpec("infra-map", "Infrastructure Map", "Enumerate public DNS and certificate data.", "infra_map", [("target", "Domain", "example.com")], "Maps public DNS records and certificate-transparency clues for a domain.", "DNS is the internet address book; this can reveal related hosts and infrastructure that should be protected." )],
    ),
    CategorySpec(
        "breaches",
        "BREACHES",
        "Breach lookup and local credential-data analysis.",
        [
            ToolSpec("lookup", "Breach Lookup", "Check configured breach intelligence sources.", "breach_lookup", [("target", "Email or username", "analyst@example.com")], "Checks configured sources for reports that an email or username appeared in a data breach.", "It helps you decide whether to change passwords and enable multi-factor authentication; do not enter secrets."),
            ToolSpec("predict-creds", "Credential Analyzer", "Profile an authorized local TXT dataset.", "analyze_passwords", [("file", "TXT file path", "./passwords.txt")], "Reviews an authorized local text dataset for password patterns and weak credential habits.", "It helps owners identify risky reuse and improve password policy; only analyze files you are authorized to use."),
        ],
    ),
]


def style_output_line(line: str) -> Text:
    """Color status markers while keeping output content literal and safe."""
    styled = Text(line)
    colors = {"[+]": "#73d6a2", "[-]": "#ff6b7a", "[!]": "#f4c95d"}
    for match in re.finditer(r"\[\+\]|\[-\]|\[!\]", line):
        styled.stylize(colors[match.group()], match.start(), match.end())
    return styled


class ScyllaState:
    def __init__(self) -> None:
        self.active_category = CATEGORIES[0]
        self.active_tool = CATEGORIES[0].tools[0]
        self.values: Dict[str, str] = {}
        self.proxy_pool = 12
        self.status = "READY"
        self.output_lines: List[str] = [
            "[+] Initializing core engine...",
            "[+] Loaded 48 active modules. Type 'help' or select a category to begin reconnaissance.",
        ]

    def write(self, message: str) -> None:
        self.output_lines.extend(str(message).splitlines())


class MainMenu(Screen):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.state = ScyllaState()
        self._command: Optional[Input] = None
        self._category_buttons: Dict[str, Button] = {}
        self._tool_buttons: Dict[str, Button] = {}
        self._tool_id_paths: Dict[str, str] = {}
        self._field_inputs: Dict[str, Input] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(ASCII_ART, id="brand-art")
        yield Static('✦ ALL IN 1 OSINT TOOL ✦  |  run "help" in any tool to see what it actually does', id="brand-subtitle")
        yield Static("[ STATUS: READY ]  [ ACTIVE TARGET: NONE ]  [ PROXY POOL: 12 ROTATING ]", id="status-bar")
        with Horizontal(id="workspace"):
            with Vertical(id="catalog-panel"):
                yield Static("CATALOG DIRECTORY", classes="panel-title")
                yield Static("48+ modular modules / v1.1", classes="muted")
                for category in CATEGORIES:
                    button = Button(f"› {category.key}/", id=f"category-{category.key}", classes="category-button")
                    self._category_buttons[category.key] = button
                    yield button
                yield Static("ACTIVE TOOL", classes="panel-title")
                yield Static("Choose a category to inspect its tools.", id="active-tool-summary", classes="muted")
            with Vertical(id="main-panel"):
                yield Static("SESSION OUTPUT WINDOW", classes="panel-title")
                yield RichLog(id="session-log", highlight=True, markup=False, wrap=True)
                with Horizontal(id="command-row"):
                    yield Static("scylla>", id="prompt-label")
                    self._command = Input(placeholder="use vulnerability/ports | set target example.com | run", id="command-input")
                    yield self._command
                yield Static("TOOL DIRECTORY", classes="panel-title")
                with VerticalScroll(id="tool-list"):
                    for category in CATEGORIES:
                        for tool in category.tools:
                            path = f"{category.key}/{tool.key}"
                            tool_id = f"tool-{category.key}-{tool.key.replace('-', '_')}"
                            button = Button(
                                f"{path:<34} {tool.name}",
                                id=tool_id,
                                classes="tool-button",
                            )
                            self._tool_buttons[path] = button
                            self._tool_id_paths[tool_id] = path
                            yield button
                yield Static("TOOL INPUTS", classes="panel-title")
                with VerticalScroll(id="input-list"):
                    for category in CATEGORIES:
                        for tool in category.tools:
                            path = f"{category.key}/{tool.key}"
                            for field_name, label, placeholder in tool.fields:
                                field_id = f"input-{category.key}-{tool.key.replace('-', '_')}-{field_name}"
                                field = Input(placeholder=f"{label}: {placeholder}", id=field_id)
                                field.add_class(f"field-{path.replace('/', '-')}")
                                self._field_inputs[f"{path}:{field_name}"] = field
                                yield field
                            if not tool.fields:
                                yield Static(f"{path}: no input required", classes=f"field-{path.replace('/', '-')}")
                yield Button("RUN SELECTED TOOL", id="run-tool", classes="run-button")
        yield Footer()

    def on_mount(self) -> None:
        self._render_log()
        self._select_category(self.state.active_category.key)
        if self._command:
            self._command.focus()

    def _render_log(self) -> None:
        log = self.query_one("#session-log", RichLog)
        log.clear()
        for line in self.state.output_lines:
            log.write(style_output_line(line))

    def _select_category(self, category_key: str) -> None:
        category = next((item for item in CATEGORIES if item.key == category_key), CATEGORIES[0])
        self.state.active_category = category
        self.state.active_tool = category.tools[0]
        for key, button in self._category_buttons.items():
            button.set_class(key == category.key, "selected")
        for path, button in self._tool_buttons.items():
            button.set_class(not path.startswith(f"{category.key}/"), "hidden")
        for path, field in self._field_inputs.items():
            field.set_class(not path.startswith(f"{category.key}/"), "hidden")
        self._select_tool(category.tools[0].key)
        self._update_status()

    def _select_tool(self, tool_key: str) -> None:
        tool = next((item for item in self.state.active_category.tools if item.key == tool_key), self.state.active_category.tools[0])
        self.state.active_tool = tool
        active_path = f"{self.state.active_category.key}/{tool.key}"
        for path, button in self._tool_buttons.items():
            button.set_class(path == active_path, "selected")
        for path, field in self._field_inputs.items():
            field.set_class(not path.startswith(f"{active_path}:"), "hidden")
        inputs = ", ".join(name for name, _, _ in tool.fields) or "none"
        self.query_one("#active-tool-summary", Static).update(
            f"{self.state.active_category.name} / {tool.key}\n{tool.description}\nInputs: {inputs}"
        )

    def _update_status(self) -> None:
        target = self.state.values.get("target") or self.state.values.get("username") or self.state.values.get("file") or "NONE"
        self.query_one("#status-bar", Static).update(
            f"[ STATUS: {self.state.status} ]  [ ACTIVE TARGET: {target} ]  [ PROXY POOL: {self.state.proxy_pool} ROTATING ]"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("category-"):
            self._select_category(button_id.removeprefix("category-"))
        elif button_id.startswith("tool-"):
            path = self._tool_id_paths.get(button_id)
            if path:
                category_key, tool_key = path.split("/", 1)
                self._select_category(category_key)
                self._select_tool(tool_key)
        elif button_id == "run-tool":
            self._sync_active_inputs()
            self.run_worker(self._run_active_tool())

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "command-input":
            command = event.value.strip()
            event.input.value = ""
            if command:
                await self.execute_command(command)
            return
        self._sync_active_inputs()

    async def execute_command(self, command: str) -> None:
        parts = command.split()
        action = parts[0].lower() if parts else ""
        self.state.write(f"scylla> {command}")
        if action == "help":
            self.state.write("Commands: use <category/tool>, set <field> <value>, run, help, clear")
            self.state.write("Tool inputs are shown under ACTIVE TOOL; select a tool before setting values.")
        elif action == "clear":
            self.state.output_lines.clear()
        elif action == "use" and len(parts) > 1:
            self._use_path(parts[1])
        elif action == "set" and len(parts) > 2:
            self._set_field(parts[1].lower(), " ".join(parts[2:]))
        elif action == "run":
            await self._run_active_tool()
        else:
            self.state.write("[!] Unknown command. Type 'help' for available commands.")
        self._render_log()
        self._update_status()

    def _use_path(self, path: str) -> None:
        normalized = path.strip("/").split("/")
        category = next((item for item in CATEGORIES if item.key == normalized[0]), None)
        if not category:
            self.state.write(f"[!] Category not found: {normalized[0]}")
            return
        self._select_category(category.key)
        if len(normalized) > 1:
            tool = next((item for item in category.tools if item.key == normalized[1]), None)
            if not tool:
                self.state.write(f"[!] Tool not found: {path}")
                return
            self._select_tool(tool.key)
        self.state.write(f"[+] Active tool: {category.key}/{self.state.active_tool.key}")

    def _set_field(self, field_name: str, value: str) -> None:
        known_fields = {name for name, _, _ in self.state.active_tool.fields}
        if field_name not in known_fields:
            self.state.write(f"[!] {self.state.active_tool.key} does not accept '{field_name}'.")
            return
        self.state.values[field_name] = value
        self.state.write(f"[+] Set {field_name}: {value}")

    def _sync_active_inputs(self) -> None:
        path = f"{self.state.active_category.key}/{self.state.active_tool.key}"
        for field_name, _, _ in self.state.active_tool.fields:
            field = self._field_inputs.get(f"{path}:{field_name}")
            if field and field.value.strip():
                self.state.values[field_name] = field.value.strip()

    async def _run_active_tool(self) -> None:
        self._sync_active_inputs()
        tool = self.state.active_tool
        missing = [name for name, _, _ in tool.fields if not self.state.values.get(name)]
        if missing:
            self.state.write(f"[!] Missing input: {', '.join(missing)}. Use 'set {missing[0]} <value>'.")
            return
        self.state.status = "RUNNING"
        self._update_status()
        self.state.write(f"[>] Executing {tool.name}...")
        self._render_log()
        result = await self.engine.run_module(self._engine_category(), tool.module_id, self._target_for_engine())
        self.state.write(result)
        self.state.status = "READY"
        self._update_status()

    def _target_for_engine(self) -> str:
        for field_name, _, _ in self.state.active_tool.fields:
            if self.state.values.get(field_name):
                return self.state.values[field_name]
        return ""

    def _engine_category(self) -> str:
        mapping = {"vulnerability": "vuln", "social": "social", "web": "infra", "temps": "temp", "dns": "infra", "breaches": "breach"}
        return mapping[self.state.active_category.key]


class CategoryMenu(Screen):
    """Compatibility wrapper for callers that still open a category directly."""

    def __init__(self, engine, cat_id, cat_name):
        super().__init__()
        self.engine = engine
        self.cat_id = cat_id
        self.cat_name = cat_name

    def compose(self) -> ComposeResult:
        yield Static(f"{self.cat_name}\n\nUse the main command center to run this module.")


class ResultsScreen(Screen):
    def __init__(self, data):
        super().__init__()
        self.data = data

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("INVESTIGATION RESULTS", classes="panel-title")
        with VerticalScroll(classes="results-box"):
            yield Static(str(self.data))
        yield Button("Back to command center", id="back", classes="menu-button")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
