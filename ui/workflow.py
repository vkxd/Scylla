import re
from typing import Dict

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, RichLog, Static

from ui.screens import ASCII_ART, CATEGORIES, CategorySpec, ToolSpec


ENGINE_CATEGORIES = {
    "vulnerability": "vuln",
    "social": "social",
    "web": "infra",
    "temps": "temp",
    "dns": "infra",
    "breaches": "breach",
}


def style_output_line(line: str) -> Text:
    """Color every status marker without interpreting user/server text as markup."""
    styled = Text(line)
    colors = {"[+]": "#73d6a2", "[-]": "#ff6b7a", "[!]": "#f4c95d"}
    for match in re.finditer(r"\[\+\]|\[-\]|\[!\]", line):
        styled.stylize(colors[match.group()], match.start(), match.end())
    return styled


def find_category(category_key: str) -> CategorySpec:
    return next(category for category in CATEGORIES if category.key == category_key)


def find_tool(category: CategorySpec, tool_key: str) -> ToolSpec:
    return next(tool for tool in category.tools if tool.key == tool_key)


class MainMenu(Screen):
    """First stage: choose an investigation category."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(ASCII_ART, id="brand-art")
        yield Static('✦ ALL IN 1 OSINT TOOL ✦  |  run "help" in any tool to see what it actually does', id="brand-subtitle")
        yield Static("[ STATUS: READY ]  [ ACTIVE CATEGORY: NONE ]  [ PROXY POOL: 12 ROTATING ]", id="status-bar")
        with VerticalScroll(id="category-screen"):
            yield Static("SELECT A CATEGORY", classes="screen-title")
            yield Static("Choose the type of investigation you want to run.", classes="muted")
            for category in CATEGORIES:
                yield Button(
                    f"> {category.key}/    {category.name}\n  {category.description}",
                    id=f"category-{category.key}",
                    classes="category-card",
                )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("category-"):
            self.app.push_screen(ToolMenu(self.engine, find_category(button_id.removeprefix("category-"))))


class ToolMenu(Screen):
    """Second stage: choose one tool from the selected category."""

    def __init__(self, engine, category: CategorySpec):
        super().__init__()
        self.engine = engine
        self.category = category

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"SCYLLA / {self.category.key}", classes="screen-title")
        yield Static(self.category.description, classes="muted")
        with VerticalScroll(id="tool-screen"):
            yield Static("SELECT A TOOL", classes="panel-title")
            for tool in self.category.tools:
                fields = ", ".join(name for name, _, _ in tool.fields) or "no input required"
                yield Button(
                    f"> {tool.key}\n  {tool.name} | inputs: {fields}\n  {tool.description}",
                    id=f"tool-{tool.key.replace('-', '_')}",
                    classes="tool-card",
                )
        yield Button("BACK TO CATEGORIES", id="back-categories", classes="secondary-button")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id == "back-categories":
            self.app.pop_screen()
        elif button_id.startswith("tool-"):
            tool_key = button_id.removeprefix("tool-").replace("_", "-")
            self.app.push_screen(ToolCli(self.engine, self.category, find_tool(self.category, tool_key)))


class ToolCli(Screen):
    """Third stage: a dedicated CLI session for one selected tool."""

    def __init__(self, engine, category: CategorySpec, tool: ToolSpec):
        super().__init__()
        self.engine = engine
        self.category = category
        self.tool = tool
        self.values: Dict[str, str] = {}
        self.status = "READY"
        self.output_lines = [
            f"[+] Selected tool: {category.key}/{tool.key}",
            f"[+] {tool.description}",
        ]
        if tool.fields:
            self.output_lines.append("[+] Required inputs: " + ", ".join(name for name, _, _ in tool.fields))
            self.output_lines.append("[>] Use 'set <field> <value>' and then 'run'.")
        else:
            self.output_lines.append("[>] This tool needs no input. Type 'run' to execute it.")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"SCYLLA / {self.category.key} / {self.tool.key}", classes="screen-title")
        yield Static(self.tool.description, classes="muted")
        yield Static("[ STATUS: READY ]", id="tool-status")
        with Vertical(id="cli-layout"):
            yield RichLog(id="tool-log", highlight=True, markup=False, wrap=True)
            with Horizontal(id="tool-command-row"):
                yield Static(f"scylla ({self.category.key}/{self.tool.key})>", id="tool-prompt-label")
                yield Input(placeholder=self._placeholder(), id="tool-command-input")
        yield Button("BACK TO TOOLS", id="back-tools", classes="secondary-button")
        yield Footer()

    def on_mount(self) -> None:
        self._render_log()
        self.query_one("#tool-command-input", Input).focus()

    def _placeholder(self) -> str:
        if not self.tool.fields:
            return "run | help | back"
        return f"set {self.tool.fields[0][0]} <value> | run | help | back"

    def _render_log(self) -> None:
        log = self.query_one("#tool-log", RichLog)
        log.clear()
        for line in self.output_lines:
            log.write(style_output_line(line))

    def _update_status(self) -> None:
        values = ", ".join(f"{key}={value}" for key, value in self.values.items()) or "no inputs set"
        self.query_one("#tool-status", Static).update(f"[ STATUS: {self.status} ]  [ {values} ]")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        event.input.value = ""
        if command:
            await self.execute_command(command)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-tools":
            self.app.pop_screen()

    async def execute_command(self, command: str) -> None:
        parts = command.split()
        action = parts[0].lower().removeprefix("/") if parts else ""
        self.output_lines.append(f"scylla ({self.category.key}/{self.tool.key})> {command}")
        if action == "help":
            self._write_help()
        elif action == "back":
            self.app.pop_screen()
            return
        elif action == "clear":
            self.output_lines.clear()
        elif action == "set" and len(parts) >= 3:
            self._set_value(parts[1].lower(), " ".join(parts[2:]))
        elif action == "run":
            await self._run_tool()
        else:
            self.output_lines.append("[!] Unknown command. Type 'help' for this tool's commands.")
        self._render_log()
        self._update_status()

    def _write_help(self) -> None:
        self.output_lines.append("ABOUT THIS TOOL")
        self.output_lines.append(f"What it does: {self.tool.what_it_does}")
        self.output_lines.append(f"Why it matters: {self.tool.why_it_matters}")
        self.output_lines.append("")
        self.output_lines.append("Commands for this tool:")
        for field_name, label, placeholder in self.tool.fields:
            self.output_lines.append(f"  set {field_name} <value>   {label} (example: {placeholder})")
        self.output_lines.append("  run                      Execute the selected tool")
        self.output_lines.append("  clear                    Clear this tool's output")
        self.output_lines.append("  back                     Return to the tool list")

    def _set_value(self, field_name: str, value: str) -> None:
        known_fields = {name for name, _, _ in self.tool.fields}
        if field_name not in known_fields:
            self.output_lines.append(f"[!] This tool does not accept '{field_name}'.")
            return
        self.values[field_name] = value
        self.output_lines.append(f"[+] Set {field_name}: {value}")

    async def _run_tool(self) -> None:
        missing = [name for name, _, _ in self.tool.fields if not self.values.get(name)]
        if missing:
            self.output_lines.append(f"[!] Missing input: {', '.join(missing)}")
            self.output_lines.append(f"[>] Set it with: set {missing[0]} <value>")
            return
        self.status = "RUNNING"
        self._update_status()
        self.output_lines.append(f"[>] Executing {self.tool.name}...")
        self._render_log()
        target = next((self.values[name] for name, _, _ in self.tool.fields), "")
        result = await self.engine.run_module(ENGINE_CATEGORIES[self.category.key], self.tool.module_id, target)
        self.output_lines.extend(str(result).splitlines())
        self.status = "READY"


CategoryMenu = MainMenu
