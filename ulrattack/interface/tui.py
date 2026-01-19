import argparse
import asyncio
import atexit
import logging
import signal
import sys
import threading
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from typing import TYPE_CHECKING, Any, ClassVar


if TYPE_CHECKING:
    from textual.timer import Timer

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.style import Style
from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static, TextArea, Tree
from textual.widgets.tree import TreeNode

from ulrattack.agents.ULRATTACKAgent import ULRATTACKAgent
from ulrattack.interface.utils import build_tui_stats_text
from ulrattack.llm.config import LLMConfig
from ulrattack.telemetry.tracer import Tracer, set_global_tracer


def get_package_version() -> str:
    try:
        return pkg_version("ulrattack-agent")
    except PackageNotFoundError:
        return "dev"


class ChatTextArea(TextArea):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_reference: ULRATTACKTUIApp | None = None

    def set_app_reference(self, app: "ULRATTACKTUIApp") -> None:
        self._app_reference = app

    def on_mount(self) -> None:
        self._update_height()

    def _on_key(self, event: events.Key) -> None:
        if event.key == "shift+enter":
            self.insert("\n")
            event.prevent_default()
            return

        if event.key == "enter" and self._app_reference:
            text_content = str(self.text)  # type: ignore[has-type]
            message = text_content.strip()
            if message:
                self.text = ""

                self._app_reference._send_user_message(message)

                event.prevent_default()
                return

        super()._on_key(event)

    @on(TextArea.Changed)  # type: ignore[misc]
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return

        line_count = self.document.line_count
        target_lines = min(max(1, line_count), 8)

        new_height = target_lines + 2

        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class SplashScreen(Static):  # type: ignore[misc]
    PRIMARY_GREEN = "#00ff41"  # Matrix green
    SECONDARY_GREEN = "#008f11"
    CYBER_CYAN = "#00d4ff"
    
    BANNER = (
        "  ██████╗████████╗██████╗ ██╗██╗  ██╗\n"
        "  ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝\n"
        "  ███████╗   ██║   ██████╔╝██║ ╚███╔╝ \n"
        "  ╚════██║   ██║   ██╔══██╗██║ ██╔██╗ \n"
        "  ███████║   ██║   ██║  ██║██║██╔╝ ██╗\n"
        "  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer: Timer | None = None
        self._panel_static: Static | None = None
        self._version = "dev"

    def compose(self) -> ComposeResult:
        self._version = get_package_version()
        self._animation_step = 0
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)

        panel_static = Static(panel, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return

        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        content = Group(
            Align.center(Text(self.BANNER.strip("\n"), style=self.PRIMARY_GREEN, justify="center")),
            Align.center(Text(" ")),
            Align.center(self._build_welcome_text()),
            Align.center(self._build_version_text()),
            Align.center(self._build_tagline_text()),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
            Align.center(Text(" ")),
            Align.center(self._build_url_text()),
        )

        return Panel.fit(content, border_style=self.PRIMARY_GREEN, padding=(1, 6))

    def _build_url_text(self) -> Text:
        text = Text()
        text.append("[ ", style=Style(color=self.SECONDARY_GREEN))
        text.append("ulrattack.ai", style=Style(color=self.CYBER_CYAN, bold=True))
        text.append(" ]", style=Style(color=self.SECONDARY_GREEN))
        return text

    def _build_welcome_text(self) -> Text:
        text = Text("欢迎使用 ", style=Style(color="white", bold=True))
        text.append("ULRATTACK", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append(" !", style=Style(color="white", bold=True))
        return text

    def _build_version_text(self) -> Text:
        return Text(f"v{self._version}", style=Style(color="#666666", dim=True))

    def _build_tagline_text(self) -> Text:
        return Text("开源AI驱动的安全渗透测试系统", style=Style(color="#888888", dim=True))

    def _build_start_line_text(self, phase: int) -> Text:
        full_text = "正在初始化 ULRATTACK 智能代理..."
        text_len = len(full_text)

        shine_pos = phase % (text_len + 8)

        text = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)

            if dist <= 1:
                style = Style(color=self.CYBER_CYAN, bold=True)
            elif dist <= 3:
                style = Style(color=self.PRIMARY_GREEN, bold=True)
            elif dist <= 5:
                style = Style(color=self.SECONDARY_GREEN)
            else:
                style = Style(color="#404040")

            text.append(char, style=style)

        return text


class HelpScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("🦉 ULRATTACK 帮助", id="help_title"),
            Label(
                "F1        显示帮助\n"
                "Ctrl+Q/C  退出程序\n"
                "ESC       停止代理\n"
                "Enter     发送消息\n"
                "Tab       切换面板\n"
                "↑/↓       导航树形列表",
                id="help_content",
            ),
            id="dialog",
        )

    def on_key(self, _event: events.Key) -> None:
        self.app.pop_screen()


class StopAgentScreen(ModalScreen):  # type: ignore[misc]
    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"⚠ 停止 '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("确定", variant="error", id="stop_agent"),
                Button("取消", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel_stop", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "stop_agent":
                cancel_button = self.query_one("#cancel_stop", Button)
                cancel_button.focus()
            else:
                stop_button = self.query_one("#stop_agent", Button)
                stop_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)
        else:
            self.app.pop_screen()


class VulnerabilityDetailScreen(ModalScreen):  # type: ignore[misc]
    """漏洞详情模态窗口"""

    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#ff0040",  # 红色 - 严重
        "high": "#ff6600",  # 橙色 - 高危
        "medium": "#ffcc00",  # 黄色 - 中危
        "low": "#00ff41",  # 绿色 - 低危
        "info": "#00d4ff",  # 青色 - 信息
    }
    
    SEVERITY_NAMES: ClassVar[dict[str, str]] = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }

    FIELD_STYLE: ClassVar[str] = "bold #00ff41"

    def __init__(self, vulnerability: dict[str, Any]) -> None:
        super().__init__()
        self.vulnerability = vulnerability

    def compose(self) -> ComposeResult:
        content = self._render_vulnerability()
        yield Grid(
            VerticalScroll(Static(content, id="vuln_detail_content"), id="vuln_detail_scroll"),
            Horizontal(
                Button("复制", variant="default", id="copy_vuln_detail"),
                Button("关闭", variant="default", id="close_vuln_detail"),
                id="vuln_detail_buttons",
            ),
            id="vuln_detail_dialog",
        )

    def on_mount(self) -> None:
        close_button = self.query_one("#close_vuln_detail", Button)
        close_button.focus()

    def _get_cvss_color(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "#ff0040"
        if cvss_score >= 7.0:
            return "#ff6600"
        if cvss_score >= 4.0:
            return "#ffcc00"
        if cvss_score >= 0.1:
            return "#00ff41"
        return "#666666"

    def _highlight_python(self, code: str) -> Text:
        try:
            from pygments.lexers import PythonLexer
            from pygments.styles import get_style_by_name

            lexer = PythonLexer()
            style = get_style_by_name("native")
            colors = {
                token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]
            }

            text = Text()
            for token_type, token_value in lexer.get_tokens(code):
                if not token_value:
                    continue
                color = None
                tt = token_type
                while tt:
                    if tt in colors:
                        color = colors[tt]
                        break
                    tt = tt.parent
                text.append(token_value, style=color)
        except (ImportError, KeyError, AttributeError):
            return Text(code)
        else:
            return text

    def _render_vulnerability(self) -> Text:  # noqa: PLR0912, PLR0915
        vuln = self.vulnerability
        text = Text()

        text.append("🐞 ")
        text.append("漏洞报告", style="bold #ff6600")

        agent_name = vuln.get("agent_name", "")
        if agent_name:
            text.append("\n\n")
            text.append("代理: ", style=self.FIELD_STYLE)
            text.append(agent_name)

        title = vuln.get("title", "")
        if title:
            text.append("\n\n")
            text.append("标题: ", style=self.FIELD_STYLE)
            text.append(title)

        severity = vuln.get("severity", "")
        if severity:
            text.append("\n\n")
            text.append("严重程度: ", style=self.FIELD_STYLE)
            severity_color = self.SEVERITY_COLORS.get(severity.lower(), "#666666")
            severity_name = self.SEVERITY_NAMES.get(severity.lower(), severity.upper())
            text.append(severity_name, style=f"bold {severity_color}")

        cvss_score = vuln.get("cvss")
        if cvss_score is not None:
            text.append("\n\n")
            text.append("CVSS 评分: ", style=self.FIELD_STYLE)
            cvss_color = self._get_cvss_color(float(cvss_score))
            text.append(str(cvss_score), style=f"bold {cvss_color}")

        target = vuln.get("target", "")
        if target:
            text.append("\n\n")
            text.append("目标: ", style=self.FIELD_STYLE)
            text.append(target)

        endpoint = vuln.get("endpoint", "")
        if endpoint:
            text.append("\n\n")
            text.append("端点: ", style=self.FIELD_STYLE)
            text.append(endpoint)

        method = vuln.get("method", "")
        if method:
            text.append("\n\n")
            text.append("方法: ", style=self.FIELD_STYLE)
            text.append(method)

        cve = vuln.get("cve", "")
        if cve:
            text.append("\n\n")
            text.append("CVE编号: ", style=self.FIELD_STYLE)
            text.append(cve)

        # CVSS breakdown
        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            cvss_parts = []
            if cvss_breakdown.get("attack_vector"):
                cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
            if cvss_breakdown.get("attack_complexity"):
                cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
            if cvss_breakdown.get("privileges_required"):
                cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
            if cvss_breakdown.get("user_interaction"):
                cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
            if cvss_breakdown.get("scope"):
                cvss_parts.append(f"S:{cvss_breakdown['scope']}")
            if cvss_breakdown.get("confidentiality"):
                cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
            if cvss_breakdown.get("integrity"):
                cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
            if cvss_breakdown.get("availability"):
                cvss_parts.append(f"A:{cvss_breakdown['availability']}")
            if cvss_parts:
                text.append("\n\n")
                text.append("CVSS 向量: ", style=self.FIELD_STYLE)
                text.append("/".join(cvss_parts), style="dim")

        description = vuln.get("description", "")
        if description:
            text.append("\n\n")
            text.append("漏洞描述", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(description)

        impact = vuln.get("impact", "")
        if impact:
            text.append("\n\n")
            text.append("影响分析", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(impact)

        technical_analysis = vuln.get("technical_analysis", "")
        if technical_analysis:
            text.append("\n\n")
            text.append("技术分析", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        poc_description = vuln.get("poc_description", "")
        if poc_description:
            text.append("\n\n")
            text.append("PoC 说明", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(poc_description)

        poc_script_code = vuln.get("poc_script_code", "")
        if poc_script_code:
            text.append("\n\n")
            text.append("PoC 代码", style=self.FIELD_STYLE)
            text.append("\n")
            text.append_text(self._highlight_python(poc_script_code))

        remediation_steps = vuln.get("remediation_steps", "")
        if remediation_steps:
            text.append("\n\n")
            text.append("修复建议", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(remediation_steps)

        return text

    def _get_markdown_report(self) -> str:  # noqa: PLR0912, PLR0915
        """获取 Markdown 格式的漏洞报告用于剪贴板"""
        vuln = self.vulnerability
        lines: list[str] = []

        # Title
        title = vuln.get("title", "未命名漏洞")
        lines.append(f"# {title}")
        lines.append("")

        # Metadata
        if vuln.get("id"):
            lines.append(f"**ID:** {vuln['id']}")
        if vuln.get("severity"):
            severity_name = self.SEVERITY_NAMES.get(vuln['severity'].lower(), vuln['severity'].upper())
            lines.append(f"**严重程度:** {severity_name}")
        if vuln.get("timestamp"):
            lines.append(f"**发现时间:** {vuln['timestamp']}")
        if vuln.get("agent_name"):
            lines.append(f"**发现代理:** {vuln['agent_name']}")
        if vuln.get("target"):
            lines.append(f"**目标:** {vuln['target']}")
        if vuln.get("endpoint"):
            lines.append(f"**端点:** {vuln['endpoint']}")
        if vuln.get("method"):
            lines.append(f"**方法:** {vuln['method']}")
        if vuln.get("cve"):
            lines.append(f"**CVE:** {vuln['cve']}")
        if vuln.get("cvss") is not None:
            lines.append(f"**CVSS:** {vuln['cvss']}")

        # CVSS Vector
        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            abbrevs = {
                "attack_vector": "AV",
                "attack_complexity": "AC",
                "privileges_required": "PR",
                "user_interaction": "UI",
                "scope": "S",
                "confidentiality": "C",
                "integrity": "I",
                "availability": "A",
            }
            parts = [
                f"{abbrevs.get(k, k)}:{v}" for k, v in cvss_breakdown.items() if v and k in abbrevs
            ]
            if parts:
                lines.append(f"**CVSS 向量:** {'/'.join(parts)}")

        # Description
        lines.append("")
        lines.append("## 漏洞描述")
        lines.append("")
        lines.append(vuln.get("description") or "暂无描述")

        # Impact
        if vuln.get("impact"):
            lines.extend(["", "## 影响分析", "", vuln["impact"]])

        # Technical Analysis
        if vuln.get("technical_analysis"):
            lines.extend(["", "## 技术分析", "", vuln["technical_analysis"]])

        # Proof of Concept
        if vuln.get("poc_description") or vuln.get("poc_script_code"):
            lines.extend(["", "## 概念验证 (PoC)", ""])
            if vuln.get("poc_description"):
                lines.append(vuln["poc_description"])
                lines.append("")
            if vuln.get("poc_script_code"):
                lines.append("```python")
                lines.append(vuln["poc_script_code"])
                lines.append("```")

        # Code Analysis
        if vuln.get("code_file") or vuln.get("code_diff"):
            lines.extend(["", "## 代码分析", ""])
            if vuln.get("code_file"):
                lines.append(f"**文件:** {vuln['code_file']}")
                lines.append("")
            if vuln.get("code_diff"):
                lines.append("**代码变更:**")
                lines.append("```diff")
                lines.append(vuln["code_diff"])
                lines.append("```")

        # Remediation
        if vuln.get("remediation_steps"):
            lines.extend(["", "## 修复建议", "", vuln["remediation_steps"]])

        lines.append("")
        return "\n".join(lines)

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy_vuln_detail":
            markdown_text = self._get_markdown_report()
            self.app.copy_to_clipboard(markdown_text)

            copy_button = self.query_one("#copy_vuln_detail", Button)
            copy_button.label = "已复制!"
            self.set_timer(1.5, lambda: setattr(copy_button, "label", "复制"))
        elif event.button.id == "close_vuln_detail":
            self.app.pop_screen()


class VulnerabilityItem(Static):  # type: ignore[misc]
    """可点击的漏洞项目"""

    def __init__(self, label: Text, vuln_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(label, **kwargs)
        self.vuln_data = vuln_data

    def on_click(self, _event: events.Click) -> None:
        """点击打开漏洞详情"""
        self.app.push_screen(VulnerabilityDetailScreen(self.vuln_data))


class VulnerabilitiesPanel(VerticalScroll):  # type: ignore[misc]
    """显示发现漏洞的滚动面板"""

    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#ff0040",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#00ff41",
        "info": "#00d4ff",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._vulnerabilities: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        return []

    def update_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> None:
        """更新漏洞列表并重新渲染"""
        if self._vulnerabilities == vulnerabilities:
            return
        self._vulnerabilities = list(vulnerabilities)
        self._render_panel()

    def _render_panel(self) -> None:
        """渲染漏洞面板内容"""
        for child in list(self.children):
            if isinstance(child, VulnerabilityItem):
                child.remove()

        if not self._vulnerabilities:
            return

        for vuln in self._vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            title = vuln.get("title", "未知漏洞")
            color = self.SEVERITY_COLORS.get(severity, "#00d4ff")

            label = Text()
            label.append("● ", style=Style(color=color))
            label.append(title, style=Style(color="#d4d4d4"))

            item = VulnerabilityItem(label, vuln, classes="vuln-item")
            self.mount(item)


class QuitScreen(ModalScreen):  # type: ignore[misc]
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("退出 ULRATTACK?", id="quit_title"),
            Grid(
                Button("确定", variant="error", id="quit"),
                Button("取消", variant="default", id="cancel"),
                id="quit_buttons",
            ),
            id="quit_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "quit":
                cancel_button = self.query_one("#cancel", Button)
                cancel_button.focus()
            else:
                quit_button = self.query_one("#quit", Button)
                quit_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.app.action_custom_quit()
        else:
            self.app.pop_screen()


class ULRATTACKTUIApp(App):  # type: ignore[misc]
    CSS_PATH = "assets/tui_styles.tcss"

    SIDEBAR_MIN_WIDTH = 100

    selected_agent_id: reactive[str | None] = reactive(default=None)
    show_splash: reactive[bool] = reactive(default=True)

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "帮助", priority=True),
        Binding("ctrl+q", "request_quit", "退出", priority=True),
        Binding("ctrl+c", "request_quit", "退出", priority=True),
        Binding("escape", "stop_selected_agent", "停止代理", priority=True),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.scan_config = self._build_scan_config(args)
        self.agent_config = self._build_agent_config(args)

        self.tracer = Tracer(self.scan_config["run_name"])
        self.tracer.set_scan_config(self.scan_config)
        set_global_tracer(self.tracer)

        self.agent_nodes: dict[str, TreeNode] = {}

        self._displayed_agents: set[str] = set()
        self._displayed_events: list[str] = []

        self._scan_thread: threading.Thread | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()

        self._spinner_frame_index: int = 0
        self._sweep_num_squares: int = 6
        self._sweep_colors: list[str] = [
            "#000000",
            "#002200",
            "#004400",
            "#006600",
            "#008800",
            "#00aa00",
            "#00cc00",
            "#00ff41",  # Matrix green
        ]
        self._dot_animation_timer: Any | None = None

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "scan_id": args.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": args.run_name,
        }

    def _build_agent_config(self, args: argparse.Namespace) -> dict[str, Any]:
        scan_mode = getattr(args, "scan_mode", "deep")
        llm_config = LLMConfig(scan_mode=scan_mode)

        config = {
            "llm_config": llm_config,
            "max_iterations": 300,
        }

        if getattr(args, "local_sources", None):
            config["local_sources"] = args.local_sources

        return config

    def _setup_cleanup_handlers(self) -> None:
        def cleanup_on_exit() -> None:
            self.tracer.cleanup()

        def signal_handler(_signum: int, _frame: Any) -> None:
            self.tracer.cleanup()
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def compose(self) -> ComposeResult:
        if self.show_splash:
            yield SplashScreen(id="splash_screen")

    def watch_show_splash(self, show_splash: bool) -> None:
        if not show_splash and self.is_mounted:
            try:
                splash = self.query_one("#splash_screen")
                splash.remove()
            except ValueError:
                pass

            main_container = Vertical(id="main_container")

            self.mount(main_container)

            content_container = Horizontal(id="content_container")
            main_container.mount(content_container)

            chat_area_container = Vertical(id="chat_area_container")

            chat_display = Static("", id="chat_display")
            chat_history = VerticalScroll(chat_display, id="chat_history")
            chat_history.can_focus = True

            status_text = Static("", id="status_text")
            keymap_indicator = Static("", id="keymap_indicator")

            agent_status_display = Horizontal(
                status_text, keymap_indicator, id="agent_status_display", classes="hidden"
            )

            chat_prompt = Static("❯ ", id="chat_prompt")
            chat_input = ChatTextArea(
                "",
                id="chat_input",
                show_line_numbers=False,
            )
            chat_input.set_app_reference(self)
            chat_input_container = Horizontal(chat_prompt, chat_input, id="chat_input_container")

            agents_tree = Tree("🤖 活跃代理", id="agents_tree")
            agents_tree.root.expand()
            agents_tree.show_root = False

            agents_tree.show_guide = True
            agents_tree.guide_depth = 3
            agents_tree.guide_style = "dashed"

            stats_display = Static("", id="stats_display")

            vulnerabilities_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")

            sidebar = Vertical(agents_tree, vulnerabilities_panel, stats_display, id="sidebar")

            content_container.mount(chat_area_container)
            content_container.mount(sidebar)

            chat_area_container.mount(chat_history)
            chat_area_container.mount(agent_status_display)
            chat_area_container.mount(chat_input_container)

            self.call_after_refresh(self._focus_chat_input)

    def _focus_chat_input(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            chat_input = self.query_one("#chat_input", ChatTextArea)
            chat_input.show_vertical_scrollbar = False
            chat_input.show_horizontal_scrollbar = False
            chat_input.focus()
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_chat_input)

    def _focus_agents_tree(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.focus()

            if agents_tree.root.children:
                first_node = agents_tree.root.children[0]
                agents_tree.select_node(first_node)
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_agents_tree)

    def on_mount(self) -> None:
        self.title = "ULRATTACK // AI渗透测试系统"

        self.set_timer(4.5, self._hide_splash_screen)

    def _hide_splash_screen(self) -> None:
        self.show_splash = False

        self._start_scan_thread()

        self.set_interval(0.25, self._update_ui_from_tracer)

    def _update_ui_from_tracer(self) -> None:
        if self.show_splash:
            return

        if len(self.screen_stack) > 1:
            return

        if not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
            agents_tree = self.query_one("#agents_tree", Tree)

            if not self._is_widget_safe(chat_history) or not self._is_widget_safe(agents_tree):
                return
        except (ValueError, Exception):
            return

        agent_updates = False
        for agent_id, agent_data in list(self.tracer.agents.items()):
            if agent_id not in self._displayed_agents:
                self._add_agent_node(agent_data)
                self._displayed_agents.add(agent_id)
                agent_updates = True
            elif self._update_agent_node(agent_id, agent_data):
                agent_updates = True

        if agent_updates:
            self._expand_new_agent_nodes()

        self._update_chat_view()

        self._update_agent_status_display()

        self._update_stats_display()

        self._update_vulnerabilities_panel()

    def _update_agent_node(self, agent_id: str, agent_data: dict[str, Any]) -> bool:
        if agent_id not in self.agent_nodes:
            return False

        try:
            agent_node = self.agent_nodes[agent_id]
            agent_name_raw = agent_data.get("name", "代理")
            status = agent_data.get("status", "running")

            status_indicators = {
                "running": "🟢",
                "waiting": "⏸️",
                "completed": "✅",
                "failed": "❌",
                "stopped": "⏹️",
                "stopping": "⏸️",
                "llm_failed": "🔴",
            }

            status_icon = status_indicators.get(status, "🔵")
            vuln_count = self._agent_vulnerability_count(agent_id)
            vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
            agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

            if agent_node.label != agent_name:
                agent_node.set_label(agent_name)
                return True

        except (KeyError, AttributeError, ValueError) as e:
            import logging

            logging.warning(f"更新代理节点标签失败: {e}")

        return False

    def _get_chat_content(
        self,
    ) -> tuple[Any, str | None]:
        if not self.selected_agent_id:
            return self._get_chat_placeholder_content(
                "从左侧树形列表选择一个代理查看其活动", "placeholder-no-agent"
            )

        events = self._gather_agent_events(self.selected_agent_id)
        streaming = self.tracer.get_streaming_content(self.selected_agent_id)

        if not events and not streaming:
            return self._get_chat_placeholder_content(
                "正在启动代理...", "placeholder-no-activity"
            )

        current_event_ids = [e["id"] for e in events]

        if not streaming and current_event_ids == self._displayed_events:
            return None, None

        self._displayed_events = current_event_ids
        return self._get_rendered_events_content(events), "chat-content"

    def _update_chat_view(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash or not self.is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(chat_history):
            return

        try:
            is_at_bottom = chat_history.scroll_y >= chat_history.max_scroll_y
        except (AttributeError, ValueError):
            is_at_bottom = True

        content, css_class = self._get_chat_content()
        if content is None:
            return

        chat_display = self.query_one("#chat_display", Static)
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class)

        if is_at_bottom:
            self.call_later(chat_history.scroll_end, animate=False)

    def _get_chat_placeholder_content(
        self, message: str, placeholder_class: str
    ) -> tuple[Text, str]:
        self._displayed_events = [placeholder_class]
        text = Text()
        text.append(message)
        return text, f"chat-placeholder {placeholder_class}"

    def _get_rendered_events_content(self, events: list[dict[str, Any]]) -> Any:
        renderables: list[Any] = []

        if not events:
            return Text()

        for event in events:
            content: Any = None

            if event["type"] == "chat":
                content = self._render_chat_content(event["data"])
            elif event["type"] == "tool":
                content = self._render_tool_content_simple(event["data"])

            if content:
                if renderables:
                    renderables.append(Text(""))
                renderables.append(content)

        if self.selected_agent_id:
            streaming = self.tracer.get_streaming_content(self.selected_agent_id)
            if streaming:
                streaming_text = self._render_streaming_content(streaming)
                if streaming_text:
                    if renderables:
                        renderables.append(Text(""))
                    renderables.append(streaming_text)

        if not renderables:
            return Text()

        if len(renderables) == 1:
            return renderables[0]

        return Group(*renderables)

    def _render_streaming_content(self, content: str) -> Any:
        from ulrattack.interface.streaming_parser import parse_streaming_content

        renderables: list[Any] = []
        segments = parse_streaming_content(content)

        for segment in segments:
            if segment.type == "text":
                from ulrattack.interface.tool_components.agent_message_renderer import (
                    AgentMessageRenderer,
                )

                text_content = AgentMessageRenderer.render_simple(segment.content)
                if renderables:
                    renderables.append(Text(""))
                renderables.append(text_content)

            elif segment.type == "tool":
                tool_renderable = self._render_streaming_tool(
                    segment.tool_name or "unknown",
                    segment.args or {},
                    segment.is_complete,
                )
                if renderables:
                    renderables.append(Text(""))
                renderables.append(tool_renderable)

        if not renderables:
            return Text()

        if len(renderables) == 1:
            return renderables[0]

        return Group(*renderables)

    def _render_streaming_tool(
        self, tool_name: str, args: dict[str, str], is_complete: bool
    ) -> Any:
        from ulrattack.interface.tool_components.registry import get_tool_renderer

        tool_data = {
            "tool_name": tool_name,
            "args": args,
            "status": "completed" if is_complete else "running",
            "result": None,
        }

        renderer = get_tool_renderer(tool_name)
        if renderer:
            widget = renderer.render(tool_data)
            return widget.renderable

        return self._render_default_streaming_tool(tool_name, args, is_complete)

    def _render_default_streaming_tool(
        self, tool_name: str, args: dict[str, str], is_complete: bool
    ) -> Text:
        text = Text()

        if is_complete:
            text.append("✓ ", style="#00ff41")
        else:
            text.append("● ", style="#ffcc00")

        text.append("调用工具 ", style="dim")
        text.append(tool_name, style="bold #00d4ff")

        if args:
            for key, value in list(args.items())[:3]:
                text.append("\n  ")
                text.append(key, style="dim")
                text.append(": ")
                display_value = value if len(value) <= 100 else value[:97] + "..."
                text.append(display_value, style="italic" if not is_complete else None)

        return text

    def _get_status_display_content(
        self, agent_id: str, agent_data: dict[str, Any]
    ) -> tuple[Text | None, Text, bool]:
        status = agent_data.get("status", "running")

        def keymap_styled(keys: list[tuple[str, str]]) -> Text:
            t = Text()
            for i, (key, action) in enumerate(keys):
                if i > 0:
                    t.append(" · ", style="dim")
                t.append(key, style="#00ff41")
                t.append(" ", style="dim")
                t.append(action, style="dim")
            return t

        simple_statuses: dict[str, tuple[str, str]] = {
            "stopping": ("代理正在停止...", ""),
            "stopped": ("代理已停止", ""),
            "completed": ("代理已完成", ""),
        }

        if status in simple_statuses:
            msg, _ = simple_statuses[status]
            text = Text()
            text.append(msg)
            return (text, Text(), False)

        if status == "llm_failed":
            error_msg = agent_data.get("error_message", "")
            text = Text()
            if error_msg:
                text.append(error_msg, style="#ff0040")
            else:
                text.append("LLM 请求失败", style="#ff0040")
            self._stop_dot_animation()
            keymap = Text()
            keymap.append("发送消息重试", style="dim")
            return (text, keymap, False)

        if status == "waiting":
            keymap = Text()
            keymap.append("发送消息继续", style="dim")
            return (Text(" "), keymap, False)

        if status == "running":
            if self._agent_has_real_activity(agent_id):
                animated_text = Text()
                animated_text.append_text(self._get_sweep_animation(self._sweep_colors))
                animated_text.append("esc", style="#00ff41")
                animated_text.append(" ", style="dim")
                animated_text.append("停止", style="dim")
                return (animated_text, keymap_styled([("ctrl-q", "退出")]), True)
            animated_text = self._get_animated_verb_text(agent_id, "初始化中")
            return (animated_text, keymap_styled([("ctrl-q", "退出")]), True)

        return (None, Text(), False)

    def _update_agent_status_display(self) -> None:
        try:
            status_display = self.query_one("#agent_status_display", Horizontal)
            status_text = self.query_one("#status_text", Static)
            keymap_indicator = self.query_one("#keymap_indicator", Static)
        except (ValueError, Exception):
            return

        widgets = [status_display, status_text, keymap_indicator]
        if not all(self._is_widget_safe(w) for w in widgets):
            return

        if not self.selected_agent_id:
            self._safe_widget_operation(status_display.add_class, "hidden")
            return

        try:
            agent_data = self.tracer.agents[self.selected_agent_id]
            content, keymap, should_animate = self._get_status_display_content(
                self.selected_agent_id, agent_data
            )

            if not content:
                self._safe_widget_operation(status_display.add_class, "hidden")
                return

            self._safe_widget_operation(status_text.update, content)
            self._safe_widget_operation(keymap_indicator.update, keymap)
            self._safe_widget_operation(status_display.remove_class, "hidden")

            if should_animate:
                self._start_dot_animation()

        except (KeyError, Exception):
            self._safe_widget_operation(status_display.add_class, "hidden")

    def _update_stats_display(self) -> None:
        try:
            stats_display = self.query_one("#stats_display", Static)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(stats_display):
            return

        stats_content = Text()

        stats_text = build_tui_stats_text(self.tracer, self.agent_config)
        if stats_text:
            stats_content.append(stats_text)

        from rich.panel import Panel

        stats_panel = Panel(
            stats_content,
            border_style="#1a1a1a",
            padding=(0, 1),
        )

        self._safe_widget_operation(stats_display.update, stats_panel)

    def _update_vulnerabilities_panel(self) -> None:
        """更新漏洞面板"""
        try:
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(vuln_panel):
            return

        vulnerabilities = self.tracer.vulnerability_reports

        if not vulnerabilities:
            self._safe_widget_operation(vuln_panel.add_class, "hidden")
            return

        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched = dict(vuln)
            report_id = vuln.get("id", "")
            agent_name = self._get_agent_name_for_vulnerability(report_id)
            if agent_name:
                enriched["agent_name"] = agent_name
            enriched_vulns.append(enriched)

        self._safe_widget_operation(vuln_panel.remove_class, "hidden")
        vuln_panel.update_vulnerabilities(enriched_vulns)

    def _get_agent_name_for_vulnerability(self, report_id: str) -> str | None:
        """获取创建漏洞报告的代理名称"""
        for _exec_id, tool_data in list(self.tracer.tool_executions.items()):
            if tool_data.get("tool_name") == "create_vulnerability_report":
                result = tool_data.get("result", {})
                if isinstance(result, dict) and result.get("report_id") == report_id:
                    agent_id = tool_data.get("agent_id")
                    if agent_id and agent_id in self.tracer.agents:
                        name: str = self.tracer.agents[agent_id].get("name", "未知代理")
                        return name
        return None

    def _get_sweep_animation(self, color_palette: list[str]) -> Text:
        text = Text()
        num_squares = self._sweep_num_squares
        num_colors = len(color_palette)

        offset = num_colors - 1
        max_pos = (num_squares - 1) + offset
        total_range = max_pos + offset
        cycle_length = total_range * 2
        frame_in_cycle = self._spinner_frame_index % cycle_length

        wave_pos = total_range - abs(total_range - frame_in_cycle)
        sweep_pos = wave_pos - offset

        dot_color = "#0a3d1f"

        for i in range(num_squares):
            dist = abs(i - sweep_pos)
            color_idx = max(0, num_colors - 1 - dist)

            if color_idx == 0:
                text.append("·", style=Style(color=dot_color))
            else:
                color = color_palette[color_idx]
                text.append("▪", style=Style(color=color))

        text.append(" ")
        return text

    def _get_animated_verb_text(self, agent_id: str, verb: str) -> Text:  # noqa: ARG002
        text = Text()
        sweep = self._get_sweep_animation(self._sweep_colors)
        text.append_text(sweep)
        parts = verb.split(" ", 1)
        text.append(parts[0], style="#00ff41")
        if len(parts) > 1:
            text.append(" ", style="dim")
            text.append(parts[1], style="dim")
        return text

    def _start_dot_animation(self) -> None:
        if self._dot_animation_timer is None:
            self._dot_animation_timer = self.set_interval(0.06, self._animate_dots)

    def _stop_dot_animation(self) -> None:
        if self._dot_animation_timer is not None:
            self._dot_animation_timer.stop()
            self._dot_animation_timer = None

    def _animate_dots(self) -> None:
        has_active_agents = False

        if self.selected_agent_id and self.selected_agent_id in self.tracer.agents:
            agent_data = self.tracer.agents[self.selected_agent_id]
            status = agent_data.get("status", "running")
            if status in ["running", "waiting"]:
                has_active_agents = True
                num_colors = len(self._sweep_colors)
                offset = num_colors - 1
                max_pos = (self._sweep_num_squares - 1) + offset
                total_range = max_pos + offset
                cycle_length = total_range * 2
                self._spinner_frame_index = (self._spinner_frame_index + 1) % cycle_length
                self._update_agent_status_display()

        if not has_active_agents:
            has_active_agents = any(
                agent_data.get("status", "running") in ["running", "waiting"]
                for agent_data in self.tracer.agents.values()
            )

        if not has_active_agents:
            self._stop_dot_animation()
            self._spinner_frame_index = 0

    def _agent_has_real_activity(self, agent_id: str) -> bool:
        initial_tools = {"scan_start_info", "subagent_start_info"}

        for _exec_id, tool_data in list(self.tracer.tool_executions.items()):
            if tool_data.get("agent_id") == agent_id:
                tool_name = tool_data.get("tool_name", "")
                if tool_name not in initial_tools:
                    return True

        streaming = self.tracer.get_streaming_content(agent_id)
        return bool(streaming and streaming.strip())

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        count = 0
        for _exec_id, tool_data in list(self.tracer.tool_executions.items()):
            if tool_data.get("agent_id") == agent_id:
                tool_name = tool_data.get("tool_name", "")
                if tool_name == "create_vulnerability_report":
                    status = tool_data.get("status", "")
                    if status == "completed":
                        result = tool_data.get("result", {})
                        if isinstance(result, dict) and result.get("success"):
                            count += 1
        return count

    def _gather_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        chat_events = [
            {
                "type": "chat",
                "timestamp": msg["timestamp"],
                "id": f"chat_{msg['message_id']}",
                "data": msg,
            }
            for msg in self.tracer.chat_messages
            if msg.get("agent_id") == agent_id
        ]

        tool_events = [
            {
                "type": "tool",
                "timestamp": tool_data["timestamp"],
                "id": f"tool_{exec_id}",
                "data": tool_data,
            }
            for exec_id, tool_data in list(self.tracer.tool_executions.items())
            if tool_data.get("agent_id") == agent_id
        ]

        events = chat_events + tool_events
        events.sort(key=lambda e: (e["timestamp"], e["id"]))
        return events

    def watch_selected_agent_id(self, _agent_id: str | None) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        self._displayed_events.clear()

        self.call_later(self._update_chat_view)
        self._update_agent_status_display()

    def _start_scan_thread(self) -> None:
        def scan_target() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                try:
                    agent = ULRATTACKAgent(self.agent_config)

                    if not self._scan_stop_event.is_set():
                        loop.run_until_complete(agent.execute_scan(self.scan_config))

                except (KeyboardInterrupt, asyncio.CancelledError):
                    logging.info("扫描被用户中断")
                except (ConnectionError, TimeoutError):
                    logging.exception("扫描过程中网络错误")
                except RuntimeError:
                    logging.exception("扫描过程中运行时错误")
                except Exception:
                    logging.exception("扫描过程中发生意外错误")
                finally:
                    loop.close()
                    self._scan_completed.set()

            except Exception:
                logging.exception("设置扫描线程时出错")
                self._scan_completed.set()

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    def _add_agent_node(self, agent_data: dict[str, Any]) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        agent_id = agent_data["id"]
        parent_id = agent_data.get("parent_id")
        status = agent_data.get("status", "running")

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return

        agent_name_raw = agent_data.get("name", "代理")

        status_indicators = {
            "running": "🟢",
            "waiting": "🟡",
            "completed": "✅",
            "failed": "❌",
            "stopped": "⏹️",
            "stopping": "⏸️",
        }

        status_icon = status_indicators.get(status, "🔵")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        try:
            if parent_id and parent_id in self.agent_nodes:
                parent_node = self.agent_nodes[parent_id]
                agent_node = parent_node.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )
                parent_node.allow_expand = True
            else:
                agent_node = agents_tree.root.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )

            agent_node.allow_expand = False
            agent_node.expand()
            self.agent_nodes[agent_id] = agent_node

            if len(self.agent_nodes) == 1:
                agents_tree.select_node(agent_node)
                self.selected_agent_id = agent_id

            self._reorganize_orphaned_agents(agent_id)
        except (AttributeError, ValueError, RuntimeError) as e:
            import logging

            logging.warning(f"添加代理节点 {agent_id} 失败: {e}")

    def _expand_new_agent_nodes(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

    def _expand_all_agent_nodes(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            self._expand_node_recursively(agents_tree.root)
        except (ValueError, Exception):
            logging.debug("树形结构未准备好，无法展开节点")

    def _expand_node_recursively(self, node: TreeNode) -> None:
        if not node.is_expanded:
            node.expand()
        for child in node.children:
            self._expand_node_recursively(child)

    def _copy_node_under(self, node_to_copy: TreeNode, new_parent: TreeNode) -> None:
        agent_id = node_to_copy.data["agent_id"]
        agent_data = self.tracer.agents.get(agent_id, {})
        agent_name_raw = agent_data.get("name", "代理")
        status = agent_data.get("status", "running")

        status_indicators = {
            "running": "🟢",
            "waiting": "🟡",
            "completed": "✅",
            "failed": "❌",
            "stopped": "⏹️",
            "stopping": "⏸️",
        }

        status_icon = status_indicators.get(status, "🔵")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}"

        new_node = new_parent.add(
            agent_name,
            data=node_to_copy.data,
        )
        new_node.allow_expand = node_to_copy.allow_expand

        self.agent_nodes[agent_id] = new_node

        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)

        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        agents_to_move = []

        for agent_id, agent_data in list(self.tracer.agents.items()):
            if (
                agent_data.get("parent_id") == new_parent_id
                and agent_id in self.agent_nodes
                and agent_id != new_parent_id
            ):
                agents_to_move.append(agent_id)

        if not agents_to_move:
            return

        parent_node = self.agent_nodes[new_parent_id]

        for child_agent_id in agents_to_move:
            if child_agent_id in self.agent_nodes:
                old_node = self.agent_nodes[child_agent_id]

                if old_node.parent is parent_node:
                    continue

                self._copy_node_under(old_node, parent_node)

                old_node.remove()

        parent_node.allow_expand = True
        parent_node.expand()

    def _render_chat_content(self, msg_data: dict[str, Any]) -> Any:
        role = msg_data.get("role")
        content = msg_data.get("content", "")
        metadata = msg_data.get("metadata", {})

        if not content:
            return None

        if role == "user":
            from ulrattack.interface.tool_components.user_message_renderer import UserMessageRenderer

            return UserMessageRenderer.render_simple(content)

        if metadata.get("interrupted"):
            streaming_result = self._render_streaming_content(content)
            interrupted_text = Text()
            interrupted_text.append("\n")
            interrupted_text.append("⚠ ", style="#ffcc00")
            interrupted_text.append("被用户中断", style="#ffcc00 dim")
            return Group(streaming_result, interrupted_text)

        from ulrattack.interface.tool_components.agent_message_renderer import AgentMessageRenderer

        return AgentMessageRenderer.render_simple(content)

    def _render_tool_content_simple(self, tool_data: dict[str, Any]) -> Any:
        tool_name = tool_data.get("tool_name", "未知工具")
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result")

        from ulrattack.interface.tool_components.registry import get_tool_renderer

        renderer = get_tool_renderer(tool_name)

        if renderer:
            widget = renderer.render(tool_data)
            return widget.renderable

        text = Text()

        if tool_name in ("llm_error_details", "sandbox_error_details"):
            return self._render_error_details(text, tool_name, args)

        text.append("→ 调用工具 ")
        text.append(tool_name, style="bold #00d4ff")

        status_styles = {
            "running": ("●", "#ffcc00"),
            "completed": ("✓", "#00ff41"),
            "failed": ("✗", "#ff0040"),
            "error": ("✗", "#ff0040"),
        }
        icon, style = status_styles.get(status, ("○", "dim"))
        text.append(" ")
        text.append(icon, style=style)

        if args:
            for k, v in list(args.items())[:5]:
                str_v = str(v)
                if len(str_v) > 500:
                    str_v = str_v[:497] + "..."
                text.append("\n  ")
                text.append(k, style="dim")
                text.append(": ")
                text.append(str_v)

        if status in ["completed", "failed", "error"] and result:
            result_str = str(result)
            if len(result_str) > 1000:
                result_str = result_str[:997] + "..."
            text.append("\n")
            text.append("结果: ", style="bold")
            text.append(result_str)

        return text

    def _render_error_details(self, text: Any, tool_name: str, args: dict[str, Any]) -> Any:
        if tool_name == "llm_error_details":
            text.append("✗ LLM 请求失败", style="#ff0040")
        else:
            text.append("✗ 沙箱初始化失败", style="#ff0040")
            if args.get("error"):
                text.append(f"\n{args['error']}", style="bold #ff0040")
        if args.get("details"):
            details = str(args["details"])
            if len(details) > 1000:
                details = details[:997] + "..."
            text.append("\n详情: ", style="dim")
            text.append(details)
        return text

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        node = event.node

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return

        if self.focused == agents_tree and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self.is_mounted:
            return

        node = event.node

        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def _send_user_message(self, message: str) -> None:
        if not self.selected_agent_id:
            return

        if self.tracer:
            streaming_content = self.tracer.get_streaming_content(self.selected_agent_id)
            if streaming_content and streaming_content.strip():
                self.tracer.clear_streaming_content(self.selected_agent_id)
                self.tracer.interrupted_content[self.selected_agent_id] = streaming_content
                self.tracer.log_chat_message(
                    content=streaming_content,
                    role="assistant",
                    agent_id=self.selected_agent_id,
                    metadata={"interrupted": True},
                )

        try:
            from ulrattack.tools.agents_graph.agents_graph_actions import _agent_instances

            if self.selected_agent_id in _agent_instances:
                agent_instance = _agent_instances[self.selected_agent_id]
                if hasattr(agent_instance, "cancel_current_execution"):
                    agent_instance.cancel_current_execution()
        except (ImportError, AttributeError, KeyError):
            pass

        if self.tracer:
            self.tracer.log_chat_message(
                content=message,
                role="user",
                agent_id=self.selected_agent_id,
            )

        try:
            from ulrattack.tools.agents_graph.agents_graph_actions import send_user_message_to_agent

            send_user_message_to_agent(self.selected_agent_id, message)

        except (ImportError, AttributeError) as e:
            import logging

            logging.warning(f"发送消息到代理 {self.selected_agent_id} 失败: {e}")

        self._displayed_events.clear()
        self._update_chat_view()

        self.call_after_refresh(self._focus_chat_input)

    def _get_agent_name(self, agent_id: str) -> str:
        try:
            if self.tracer and agent_id in self.tracer.agents:
                agent_name = self.tracer.agents[agent_id].get("name")
                if isinstance(agent_name, str):
                    return agent_name
        except (KeyError, AttributeError) as e:
            logging.warning(f"无法获取代理 {agent_id} 的名称: {e}")
        return "未知代理"

    def action_toggle_help(self) -> None:
        if self.show_splash or not self.is_mounted:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return

        if len(self.screen_stack) > 1:
            return

        self.push_screen(HelpScreen())

    def action_request_quit(self) -> None:
        if self.show_splash or not self.is_mounted:
            self.action_custom_quit()
            return

        if len(self.screen_stack) > 1:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            self.action_custom_quit()
            return

        self.push_screen(QuitScreen())

    def action_stop_selected_agent(self) -> None:
        if self.show_splash or not self.is_mounted:
            return

        if len(self.screen_stack) > 1:
            self.pop_screen()
            return

        if not self.selected_agent_id:
            return

        agent_name, should_stop = self._validate_agent_for_stopping()
        if not should_stop:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        self.push_screen(StopAgentScreen(agent_name, self.selected_agent_id))

    def _validate_agent_for_stopping(self) -> tuple[str, bool]:
        agent_name = "未知代理"

        try:
            if self.tracer and self.selected_agent_id in self.tracer.agents:
                agent_data = self.tracer.agents[self.selected_agent_id]
                agent_name = agent_data.get("name", "未知代理")

                agent_status = agent_data.get("status", "running")
                if agent_status not in ["running"]:
                    return agent_name, False

                agent_events = self._gather_agent_events(self.selected_agent_id)
                if not agent_events:
                    return agent_name, False

                return agent_name, True

        except (KeyError, AttributeError, ValueError) as e:
            import logging

            logging.warning(f"收集代理事件失败: {e}")

        return agent_name, False

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        self.pop_screen()

        try:
            from ulrattack.tools.agents_graph.agents_graph_actions import stop_agent

            result = stop_agent(agent_id)

            import logging

            if result.get("success"):
                logging.info(f"停止请求已发送到代理: {result.get('message', '未知')}")
            else:
                logging.warning(f"停止代理失败: {result.get('error', '未知错误')}")

        except Exception:
            import logging

            logging.exception(f"停止代理 {agent_id} 失败")

    def action_custom_quit(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_stop_event.set()

            self._scan_thread.join(timeout=1.0)

        self.tracer.cleanup()

        self.exit()

    def _is_widget_safe(self, widget: Any) -> bool:
        try:
            _ = widget.screen
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return bool(widget.is_mounted)

    def _safe_widget_operation(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> bool:
        try:
            operation(*args, **kwargs)
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return True

    def on_resize(self, event: events.Resize) -> None:
        if self.show_splash or not self.is_mounted:
            return

        try:
            sidebar = self.query_one("#sidebar", Vertical)
            chat_area = self.query_one("#chat_area_container", Vertical)
        except (ValueError, Exception):
            return

        if event.size.width < self.SIDEBAR_MIN_WIDTH:
            sidebar.add_class("-hidden")
            chat_area.add_class("-full-width")
        else:
            sidebar.remove_class("-hidden")
            chat_area.remove_class("-full-width")


async def run_tui(args: argparse.Namespace) -> None:
    """以交互式 TUI 模式运行 ULRATTACK"""
    app = ULRATTACKTUIApp(args)
    await app.run_async()
