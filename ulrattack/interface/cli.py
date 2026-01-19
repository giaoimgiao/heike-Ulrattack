import atexit
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from ulrattack.agents.ULRATTACKAgent import ULRATTACKAgent
from ulrattack.llm.config import LLMConfig
from ulrattack.telemetry.tracer import Tracer, set_global_tracer

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    start_text = Text()
    start_text.append("🦉 ", style="bold white")
    start_text.append("ULRATTACK 网络安全智能代理", style="bold #00ff41")

    target_text = Text()
    if len(args.targets_info) == 1:
        target_text.append("🎯 目标: ", style="bold #00d4ff")
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append("🎯 目标: ", style="bold #00d4ff")
        target_text.append(f"{len(args.targets_info)} 个目标\n", style="bold white")
        for i, target_info in enumerate(args.targets_info):
            target_text.append("   • ", style="dim white")
            target_text.append(target_info["original"], style="white")
            if i < len(args.targets_info) - 1:
                target_text.append("\n")

    results_text = Text()
    results_text.append("📊 结果保存至: ", style="bold #00d4ff")
    results_text.append(f"ulrattack_runs/{args.run_name}", style="bold white")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("⏱️  ", style="dim")
    note_text.append("根据目标复杂度,扫描可能需要一些时间. ", style="dim")
    note_text.append("发现的漏洞将实时显示.", style="dim")

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            note_text,
        ),
        title="[bold #00ff41]🛡️  ULRATTACK 渗透测试已启动",
        title_align="center",
        border_style="#00ff41",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
    }

    llm_config = LLMConfig(scan_mode=scan_mode)
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": 300,
        "non_interactive": True,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    def display_vulnerability(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")

        vuln_text = format_vulnerability_report(report)

        vuln_panel = Panel(
            vuln_text,
            title=f"[bold #ff0040]{report_id.upper()}",
            title_align="left",
            border_style="#ff0040",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        tracer.cleanup()

    def signal_handler(_signum: int, _frame: Any) -> None:
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("🦉 ", style="bold white")
        status_text.append("正在执行渗透测试...", style="bold #00ff41")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)

        return Panel(
            status_text,
            title="[bold #00ff41]🔍 实时渗透测试状态",
            title_align="center",
            border_style="#00ff41",
            padding=(1, 2),
        )

    try:
        console.print()

        with Live(
            create_live_status(), console=console, refresh_per_second=2, transient=False
        ) as live:
            stop_updates = threading.Event()

            def update_status() -> None:
                while not stop_updates.is_set():
                    try:
                        live.update(create_live_status())
                        time.sleep(2)
                    except Exception:  # noqa: BLE001
                        break

            update_thread = threading.Thread(target=update_status, daemon=True)
            update_thread.start()

            try:
                agent = ULRATTACKAgent(agent_config)
                result = await agent.execute_scan(scan_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "未知错误")
                    error_details = result.get("details")
                    console.print()
                    console.print(f"[bold #ff0040]❌ 渗透测试失败:[/] {error_msg}")
                    if error_details:
                        console.print(f"[dim]{error_details}[/]")
                    console.print()
                    sys.exit(1)
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold #ff0040]渗透测试过程中发生错误:[/] {e}")
        raise

    if tracer.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("📄 ", style="bold #00d4ff")
        final_report_text.append("渗透测试最终报告", style="bold #00d4ff")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold #00d4ff]📊 渗透测试总结",
            title_align="center",
            border_style="#00d4ff",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
