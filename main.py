from textual.app import App

from core.engine import ScyllaEngine
from ui.workflow import MainMenu


class ScyllaApp(App):
    CSS_PATH = "ui/scylla.tcss"
    BINDINGS = [("q", "quit", "Quit"), ("escape", "app.pop_screen", "Back")]

    def __init__(self):
        super().__init__()
        self.engine = ScyllaEngine()

    def on_mount(self) -> None:
        self.push_screen(MainMenu(self.engine))

    async def on_shutdown(self) -> None:
        await self.engine.close()


if __name__ == "__main__":
    ScyllaApp().run()
