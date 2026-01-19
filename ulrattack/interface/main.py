#!/usr/bin/env python3
"""
ULRATTACK 智能代理接口
"""

import argparse
import asyncio
import logging
import shutil
import sys
from pathlib import Path
from typing import Any

import litellm
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ulrattack.config import Config, apply_saved_config, save_current_config


apply_saved_config()

from ulrattack.interface.cli import run_cli  # noqa: E402
from ulrattack.interface.tui import run_tui  # noqa: E402
from ulrattack.interface.utils import (  # noqa: E402
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    rewrite_localhost_targets,
    validate_llm_response,
)
from ulrattack.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME  # noqa: E402
from ulrattack.telemetry import posthog  # noqa: E402
from ulrattack.telemetry.tracer import get_global_tracer  # noqa: E402


logging.getLogger().setLevel(logging.ERROR)


def validate_environment() -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    if not Config.get("ulrattack_llm"):
        missing_required_vars.append("ULRATTACK_LLM")

    has_base_url = any(
        [
            Config.get("llm_api_base"),
            Config.get("openai_api_base"),
            Config.get("litellm_base_url"),
            Config.get("ollama_api_base"),
        ]
    )

    if not Config.get("llm_api_key"):
        missing_optional_vars.append("LLM_API_KEY")

    if not has_base_url:
        missing_optional_vars.append("LLM_API_BASE")

    if not Config.get("perplexity_api_key"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if not Config.get("ulrattack_reasoning_effort"):
        missing_optional_vars.append("ULRATTACK_REASONING_EFFORT")

    if missing_required_vars:
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("缺少必需的环境变量", style="bold #ff0040")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold #ffcc00")
            error_text.append(" 未设置\n", style="white")

        if missing_optional_vars:
            error_text.append("\n可选环境变量:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim #ffcc00")
                error_text.append(" 未设置\n", style="dim white")

        error_text.append("\n必需的环境变量:\n", style="white")
        for var in missing_required_vars:
            if var == "ULRATTACK_LLM":
                error_text.append("• ", style="white")
                error_text.append("ULRATTACK_LLM", style="bold #00d4ff")
                error_text.append(
                    " - litellm 使用的模型名称 (例如 'openai/gpt-5')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\n可选环境变量:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold #00d4ff")
                    error_text.append(
                        " - LLM 提供商的 API 密钥 "
                        "(本地模型、Vertex AI、AWS 等不需要)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold #00d4ff")
                    error_text.append(
                        " - 使用本地模型时的自定义 API 地址 (如 Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold #00d4ff")
                    error_text.append(
                        " - Perplexity AI 网络搜索的 API 密钥 (启用实时研究功能)\n",
                        style="white",
                    )
                elif var == "ULRATTACK_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("ULRATTACK_REASONING_EFFORT", style="bold #00d4ff")
                    error_text.append(
                        " - 推理深度级别: none, minimal, low, medium, high, xhigh "
                        "(默认: high)\n",
                        style="white",
                    )

        error_text.append("\n配置示例:\n", style="white")
        error_text.append("export ULRATTACK_LLM='openai/gpt-5'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# 本地模型、Vertex AI、AWS 等不需要\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# 仅本地模型需要\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "ULRATTACK_REASONING_EFFORT":
                    error_text.append(
                        "export ULRATTACK_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 配置错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        console = Console()
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("DOCKER 未安装", style="bold #ff0040")
        error_text.append("\n\n", style="white")
        error_text.append("在系统 PATH 中未找到 'docker' 命令行工具.\n", style="white")
        error_text.append(
            "请安装 Docker 并确保 'docker' 命令可用.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 启动错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


async def warm_up_llm() -> None:
    console = Console()

    try:
        model_name = Config.get("ulrattack_llm")
        api_key = Config.get("llm_api_key")
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        llm_timeout = int(Config.get("llm_timeout") or "300")

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": test_messages,
            "timeout": llm_timeout,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        response = litellm.completion(**completion_kwargs)

        validate_llm_response(response)

    except Exception as e:  # noqa: BLE001
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("LLM 连接失败", style="bold #ff0040")
        error_text.append("\n\n", style="white")
        error_text.append("无法连接到语言模型.\n", style="white")
        error_text.append("请检查配置后重试.\n", style="white")
        error_text.append(f"\n错误: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 启动错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("ulrattack-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ULRATTACK 多代理网络安全渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # Web 应用渗透测试
  ulrattack --target https://example.com

  # GitHub 仓库分析
  ulrattack --target https://github.com/user/repo
  ulrattack --target git@github.com:user/repo.git

  # 本地代码分析
  ulrattack --target ./my-project

  # 域名渗透测试
  ulrattack --target example.com

  # IP 地址渗透测试
  ulrattack --target 192.168.1.42

  # 多目标 (如白盒测试 - 源代码 + 部署应用)
  ulrattack --target https://github.com/user/repo --target https://example.com
  ulrattack --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # 自定义指令 (内联)
  ulrattack --target example.com --instruction "专注于认证漏洞"

  # 自定义指令 (从文件)
  ulrattack --target example.com --instruction-file ./instructions.txt
  ulrattack --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ulrattack {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        action="append",
        help="测试目标 (URL、仓库、本地目录路径、域名或 IP 地址). "
        "可多次指定以进行多目标扫描.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="渗透测试的自定义指令. 可以是: "
        "特定漏洞类型 (如 '专注于 IDOR 和 XSS'), "
        "测试方法 (如 '进行全面的认证测试'), "
        "测试凭据 (如 '使用以下凭据访问应用: admin:password123'), "
        "或关注领域 (如 '检查登录 API 端点的安全问题').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="包含详细自定义指令的文件路径. "
        "当指令较长或复杂时使用此选项 "
        "(例如 '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "非交互模式运行 (无 TUI, 完成后退出). "
            "默认为带 TUI 的交互模式."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "扫描模式: "
            "'quick' 用于快速 CI/CD 检查, "
            "'standard' 用于常规测试, "
            "'deep' 用于全面安全审查 (默认). "
            "默认: deep."
        ),
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "不能同时指定 --instruction 和 --instruction-file. 请选择其一."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"指令文件 '{instruction_path}' 为空")
        except Exception as e:  # noqa: BLE001
            parser.error(f"读取指令文件 '{instruction_path}' 失败: {e}")

    args.targets_info = []
    for target in args.target:
        try:
            target_type, target_dict = infer_target_type(target)

            if target_type == "local_code":
                display_target = target_dict.get("target_path", target)
            else:
                display_target = target

            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            parser.error(f"无效的目标 '{target}'")

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    has_vulnerabilities = tracer and len(tracer.vulnerability_reports) > 0

    completion_text = Text()
    if scan_completed:
        completion_text.append("🦉 ", style="bold white")
        completion_text.append("代理已完成", style="bold #00ff41")
        completion_text.append(" • ", style="dim white")
        completion_text.append("渗透测试完成", style="white")
    else:
        completion_text.append("🦉 ", style="bold white")
        completion_text.append("会话已结束", style="bold #ffcc00")
        completion_text.append(" • ", style="dim white")
        completion_text.append("渗透测试被用户中断", style="white")

    stats_text = build_final_stats_text(tracer)

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

    panel_parts = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    if scan_completed or has_vulnerabilities:
        results_text = Text()
        results_text.append("📊 结果已保存至: ", style="bold #00d4ff")
        results_text.append(str(results_path), style="bold #ffcc00")
        panel_parts.extend(["\n\n", results_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#00ff41" if scan_completed else "#ffcc00"

    panel = Panel(
        panel_content,
        title="[bold #00ff41]🛡️  ULRATTACK 网络安全智能代理",
        title_align="center",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print("[dim]🌐 官网:[/] [#00d4ff]https://ulrattack.ai[/]")
    console.print("[dim]💬 Discord:[/] [#00d4ff]https://discord.gg/YjKFvEZSdZ[/]")
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    if image_exists(client, Config.get("ulrattack_image")):  # type: ignore[arg-type]
        return

    console.print()
    console.print(f"[bold #00d4ff]🐳 正在拉取 Docker 镜像:[/] {Config.get('ulrattack_image')}")
    console.print("[dim #ffcc00]首次运行需要下载，可能需要几分钟...[/]")
    console.print()

    with console.status("[bold #00d4ff]正在下载镜像层...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(Config.get("ulrattack_image"), stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            console.print()
            error_text = Text()
            error_text.append("❌ ", style="bold #ff0040")
            error_text.append("镜像拉取失败", style="bold #ff0040")
            error_text.append("\n\n", style="white")
            error_text.append(f"无法下载: {Config.get('ulrattack_image')}\n", style="white")
            error_text.append(str(e), style="dim #ff0040")

            panel = Panel(
                error_text,
                title="[bold #ff0040]🛡️  DOCKER 拉取错误",
                title_align="center",
                border_style="#ff0040",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    success_text = Text()
    success_text.append("✅ ", style="bold #00ff41")
    success_text.append("Docker 镜像拉取成功", style="#00ff41")
    console.print(success_text)
    console.print()


def main() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    save_current_config()

    args.run_name = generate_run_name(args.targets_info)

    for target_info in args.targets_info:
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(repo_url, args.run_name, dest_name)
            target_info["details"]["cloned_repo_path"] = cloned_path

    args.local_sources = collect_local_sources(args.targets_info)

    is_whitebox = bool(args.local_sources)

    posthog.start(
        model=Config.get("ulrattack_llm"),
        scan_mode=args.scan_mode,
        is_whitebox=is_whitebox,
        interactive=not args.non_interactive,
        has_instructions=bool(args.instruction),
    )

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        exit_reason = "error"
        posthog.error("unhandled_exception", str(e))
        raise
    finally:
        tracer = get_global_tracer()
        if tracer:
            posthog.end(tracer, exit_reason=exit_reason)

    results_path = Path("ulrattack_runs") / args.run_name
    display_completion_message(args, results_path)

    if args.non_interactive:
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
