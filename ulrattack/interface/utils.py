import ipaddress
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


# Token 格式化工具
def format_token_count(count: float) -> str:
    count = int(count)
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 1_000:
        return f"{count / 1_000:.1f}K"
    return str(count)


# 显示工具
def get_severity_color(severity: str) -> str:
    severity_colors = {
        "critical": "#ff0040",  # 红色 - 严重
        "high": "#ff6600",      # 橙色 - 高危
        "medium": "#ffcc00",    # 黄色 - 中危
        "low": "#00ff41",       # 绿色 - 低危
        "info": "#00d4ff",      # 青色 - 信息
    }
    return severity_colors.get(severity, "#666666")


def get_cvss_color(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "#ff0040"
    if cvss_score >= 7.0:
        return "#ff6600"
    if cvss_score >= 4.0:
        return "#ffcc00"
    if cvss_score >= 0.1:
        return "#00ff41"
    return "#666666"


# 严重程度中文映射
SEVERITY_NAMES = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def format_vulnerability_report(report: dict[str, Any]) -> Text:  # noqa: PLR0912, PLR0915
    """格式化漏洞报告用于 CLI 显示"""
    field_style = "bold #00ff41"

    text = Text()

    title = report.get("title", "")
    if title:
        text.append("漏洞报告", style="bold #ff6600")
        text.append("\n\n")
        text.append("标题: ", style=field_style)
        text.append(title)

    severity = report.get("severity", "")
    if severity:
        text.append("\n\n")
        text.append("严重程度: ", style=field_style)
        severity_color = get_severity_color(severity.lower())
        severity_name = SEVERITY_NAMES.get(severity.lower(), severity.upper())
        text.append(severity_name, style=f"bold {severity_color}")

    cvss = report.get("cvss")
    if cvss is not None:
        text.append("\n\n")
        text.append("CVSS 评分: ", style=field_style)
        cvss_color = get_cvss_color(cvss)
        text.append(f"{cvss:.1f}", style=f"bold {cvss_color}")

    target = report.get("target")
    if target:
        text.append("\n\n")
        text.append("目标: ", style=field_style)
        text.append(target)

    endpoint = report.get("endpoint")
    if endpoint:
        text.append("\n\n")
        text.append("端点: ", style=field_style)
        text.append(endpoint)

    method = report.get("method")
    if method:
        text.append("\n\n")
        text.append("方法: ", style=field_style)
        text.append(method)

    cve = report.get("cve")
    if cve:
        text.append("\n\n")
        text.append("CVE编号: ", style=field_style)
        text.append(cve)

    cvss_breakdown = report.get("cvss_breakdown", {})
    if cvss_breakdown:
        text.append("\n\n")
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
            text.append("CVSS 向量: ", style=field_style)
            text.append("/".join(cvss_parts), style="dim")

    description = report.get("description")
    if description:
        text.append("\n\n")
        text.append("漏洞描述", style=field_style)
        text.append("\n")
        text.append(description)

    impact = report.get("impact")
    if impact:
        text.append("\n\n")
        text.append("影响分析", style=field_style)
        text.append("\n")
        text.append(impact)

    technical_analysis = report.get("technical_analysis")
    if technical_analysis:
        text.append("\n\n")
        text.append("技术分析", style=field_style)
        text.append("\n")
        text.append(technical_analysis)

    poc_description = report.get("poc_description")
    if poc_description:
        text.append("\n\n")
        text.append("PoC 说明", style=field_style)
        text.append("\n")
        text.append(poc_description)

    poc_script_code = report.get("poc_script_code")
    if poc_script_code:
        text.append("\n\n")
        text.append("PoC 代码", style=field_style)
        text.append("\n")
        text.append(poc_script_code, style="dim")

    code_file = report.get("code_file")
    if code_file:
        text.append("\n\n")
        text.append("代码文件: ", style=field_style)
        text.append(code_file)

    code_before = report.get("code_before")
    if code_before:
        text.append("\n\n")
        text.append("修复前代码", style=field_style)
        text.append("\n")
        text.append(code_before, style="dim")

    code_after = report.get("code_after")
    if code_after:
        text.append("\n\n")
        text.append("修复后代码", style=field_style)
        text.append("\n")
        text.append(code_after, style="dim")

    code_diff = report.get("code_diff")
    if code_diff:
        text.append("\n\n")
        text.append("代码差异", style=field_style)
        text.append("\n")
        text.append(code_diff, style="dim")

    remediation_steps = report.get("remediation_steps")
    if remediation_steps:
        text.append("\n\n")
        text.append("修复建议", style=field_style)
        text.append("\n")
        text.append(remediation_steps)

    return text


def _build_vulnerability_stats(stats_text: Text, tracer: Any) -> None:
    """构建漏洞统计部分"""
    vuln_count = len(tracer.vulnerability_reports)

    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in tracer.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        stats_text.append("🔍 发现漏洞: ", style="bold #ff0040")

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_name = SEVERITY_NAMES.get(severity, severity.upper())
                severity_text = Text()
                severity_text.append(f"{severity_name}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append(" (总计: ", style="dim white")
        stats_text.append(str(vuln_count), style="bold #ffcc00")
        stats_text.append(")", style="dim white")
        stats_text.append("\n")
    else:
        stats_text.append("🔍 发现漏洞: ", style="bold #00ff41")
        stats_text.append("0", style="bold white")
        stats_text.append(" (未检测到可利用的漏洞)", style="dim #00ff41")
        stats_text.append("\n")


def _build_llm_stats(stats_text: Text, total_stats: dict[str, Any]) -> None:
    """构建 LLM 使用统计部分"""
    if total_stats["requests"] > 0:
        stats_text.append("\n")
        stats_text.append("📥 输入Token: ", style="bold #00d4ff")
        stats_text.append(format_token_count(total_stats["input_tokens"]), style="bold white")

        if total_stats["cached_tokens"] > 0:
            stats_text.append(" • ", style="dim white")
            stats_text.append("⚡ 缓存Token: ", style="bold #00ff41")
            stats_text.append(format_token_count(total_stats["cached_tokens"]), style="bold white")

        stats_text.append(" • ", style="dim white")
        stats_text.append("📤 输出Token: ", style="bold #00d4ff")
        stats_text.append(format_token_count(total_stats["output_tokens"]), style="bold white")

        if total_stats["cost"] > 0:
            stats_text.append(" • ", style="dim white")
            stats_text.append("💰 总费用: ", style="bold #00d4ff")
            stats_text.append(f"${total_stats['cost']:.4f}", style="bold #ffcc00")
    else:
        stats_text.append("\n")
        stats_text.append("💰 总费用: ", style="bold #00d4ff")
        stats_text.append("$0.0000 ", style="bold #ffcc00")
        stats_text.append("• ", style="bold white")
        stats_text.append("📊 Token: ", style="bold #00d4ff")
        stats_text.append("0", style="bold white")


def build_final_stats_text(tracer: Any) -> Text:
    """构建最终输出的统计文本"""
    stats_text = Text()
    if not tracer:
        return stats_text

    _build_vulnerability_stats(stats_text, tracer)

    tool_count = tracer.get_real_tool_count()
    agent_count = len(tracer.agents)

    stats_text.append("🤖 使用代理: ", style="bold #00d4ff")
    stats_text.append(str(agent_count), style="bold white")
    stats_text.append(" • ", style="dim white")
    stats_text.append("🛠️ 工具调用: ", style="bold #00d4ff")
    stats_text.append(str(tool_count), style="bold white")

    llm_stats = tracer.get_total_llm_stats()
    _build_llm_stats(stats_text, llm_stats["total"])

    return stats_text


def build_live_stats_text(tracer: Any, agent_config: dict[str, Any] | None = None) -> Text:
    stats_text = Text()
    if not tracer:
        return stats_text

    if agent_config:
        llm_config = agent_config["llm_config"]
        model = getattr(llm_config, "model_name", "未知")
        stats_text.append(f"🧠 模型: {model}")
        stats_text.append("\n")

    vuln_count = len(tracer.vulnerability_reports)
    tool_count = tracer.get_real_tool_count()
    agent_count = len(tracer.agents)

    stats_text.append("🔍 漏洞: ", style="bold white")
    stats_text.append(f"{vuln_count}", style="dim white")
    stats_text.append("\n")
    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in tracer.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_name = SEVERITY_NAMES.get(severity, severity.upper())
                severity_text = Text()
                severity_text.append(f"{severity_name}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("\n")

    stats_text.append("🤖 代理: ", style="bold white")
    stats_text.append(str(agent_count), style="dim white")
    stats_text.append(" • ", style="dim white")
    stats_text.append("🛠️ 工具: ", style="bold white")
    stats_text.append(str(tool_count), style="dim white")

    llm_stats = tracer.get_total_llm_stats()
    total_stats = llm_stats["total"]

    stats_text.append("\n")

    stats_text.append("📥 输入: ", style="bold white")
    stats_text.append(format_token_count(total_stats["input_tokens"]), style="dim white")

    stats_text.append(" • ", style="dim white")
    stats_text.append("⚡ ", style="bold white")
    stats_text.append("缓存: ", style="bold white")
    stats_text.append(format_token_count(total_stats["cached_tokens"]), style="dim white")

    stats_text.append("\n")

    stats_text.append("📤 输出: ", style="bold white")
    stats_text.append(format_token_count(total_stats["output_tokens"]), style="dim white")

    stats_text.append(" • ", style="dim white")
    stats_text.append("💰 费用: ", style="bold white")
    stats_text.append(f"${total_stats['cost']:.4f}", style="dim white")

    return stats_text


def build_tui_stats_text(tracer: Any, agent_config: dict[str, Any] | None = None) -> Text:
    stats_text = Text()
    if not tracer:
        return stats_text

    if agent_config:
        llm_config = agent_config["llm_config"]
        model = getattr(llm_config, "model_name", "未知")
        stats_text.append(model, style="dim")

    llm_stats = tracer.get_total_llm_stats()
    total_stats = llm_stats["total"]

    total_tokens = total_stats["input_tokens"] + total_stats["output_tokens"]
    if total_tokens > 0:
        stats_text.append("\n")
        stats_text.append(f"{format_token_count(total_tokens)} tokens", style="dim")

    if total_stats["cost"] > 0:
        stats_text.append("\n")
        stats_text.append(f"${total_stats['cost']:.2f} 费用", style="dim")

    return stats_text


# 名称生成工具


def _slugify_for_run_name(text: str, max_length: int = 32) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text or "pentest"


def _derive_target_label_for_run_name(targets_info: list[dict[str, Any]] | None) -> str:  # noqa: PLR0911
    if not targets_info:
        return "pentest"

    first = targets_info[0]
    target_type = first.get("type")
    details = first.get("details", {}) or {}
    original = first.get("original", "") or ""

    if target_type == "web_application":
        url = details.get("target_url", original)
        try:
            parsed = urlparse(url)
            return str(parsed.netloc or parsed.path or url)
        except Exception:  # noqa: BLE001
            return str(url)

    if target_type == "repository":
        repo = details.get("target_repo", original)
        parsed = urlparse(repo)
        path = parsed.path or repo
        name = path.rstrip("/").split("/")[-1] or path
        if name.endswith(".git"):
            name = name[:-4]
        return str(name)

    if target_type == "local_code":
        path_str = details.get("target_path", original)
        try:
            return str(Path(path_str).name or path_str)
        except Exception:  # noqa: BLE001
            return str(path_str)

    if target_type == "ip_address":
        return str(details.get("target_ip", original) or original)

    return str(original or "pentest")


def generate_run_name(targets_info: list[dict[str, Any]] | None = None) -> str:
    base_label = _derive_target_label_for_run_name(targets_info)
    slug = _slugify_for_run_name(base_label)

    random_suffix = secrets.token_hex(2)

    return f"{slug}_{random_suffix}"


# 目标处理工具
def infer_target_type(target: str) -> tuple[str, dict[str, str]]:  # noqa: PLR0911
    if not target or not isinstance(target, str):
        raise ValueError("目标必须是非空字符串")

    target = target.strip()

    lower_target = target.lower()
    bare_repo_prefixes = (
        "github.com/",
        "www.github.com/",
        "gitlab.com/",
        "www.gitlab.com/",
        "bitbucket.org/",
        "www.bitbucket.org/",
    )
    if any(lower_target.startswith(p) for p in bare_repo_prefixes):
        return "repository", {"target_repo": f"https://{target}"}

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if any(
            host in parsed.netloc.lower() for host in ["github.com", "gitlab.com", "bitbucket.org"]
        ):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ip_address", {"target_ip": str(ip_obj)}

    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                resolved = path.resolve()
                return "local_code", {"target_path": str(resolved)}
            raise ValueError(f"路径存在但不是目录: {target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"无效路径: {target} - {e!s}") from e

    if target.startswith("git@") or target.endswith(".git"):
        return "repository", {"target_repo": target}

    if "." in target and "/" not in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return "web_application", {"target_url": f"https://{target}"}

    raise ValueError(
        f"无效目标: {target}\n"
        "目标必须是以下之一:\n"
        "- 有效的 URL (http:// 或 https://)\n"
        "- Git 仓库 URL (https://github.com/... 或 git@github.com:...)\n"
        "- 本地目录路径\n"
        "- 域名 (如 example.com)\n"
        "- IP 地址 (如 192.168.1.10)"
    )


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    return sanitized or "target"


def derive_repo_base_name(repo_url: str) -> str:
    if repo_url.endswith("/"):
        repo_url = repo_url[:-1]

    if ":" in repo_url and repo_url.startswith("git@"):
        path_part = repo_url.split(":", 1)[1]
    else:
        path_part = urlparse(repo_url).path or repo_url

    candidate = path_part.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    return sanitize_name(candidate or "repository")


def derive_local_base_name(path_str: str) -> str:
    try:
        base = Path(path_str).resolve().name
    except (OSError, RuntimeError):
        base = Path(path_str).name
    return sanitize_name(base or "workspace")


def assign_workspace_subdirs(targets_info: list[dict[str, Any]]) -> None:
    name_counts: dict[str, int] = {}

    for target in targets_info:
        target_type = target["type"]
        details = target["details"]

        base_name: str | None = None
        if target_type == "repository":
            base_name = derive_repo_base_name(details["target_repo"])
        elif target_type == "local_code":
            base_name = derive_local_base_name(details.get("target_path", "local"))

        if base_name is None:
            continue

        count = name_counts.get(base_name, 0) + 1
        name_counts[base_name] = count

        workspace_subdir = base_name if count == 1 else f"{base_name}-{count}"

        details["workspace_subdir"] = workspace_subdir


def collect_local_sources(targets_info: list[dict[str, Any]]) -> list[dict[str, str]]:
    local_sources: list[dict[str, str]] = []

    for target_info in targets_info:
        details = target_info["details"]
        workspace_subdir = details.get("workspace_subdir")

        if target_info["type"] == "local_code" and "target_path" in details:
            local_sources.append(
                {
                    "source_path": details["target_path"],
                    "workspace_subdir": workspace_subdir,
                }
            )

        elif target_info["type"] == "repository" and "cloned_repo_path" in details:
            local_sources.append(
                {
                    "source_path": details["cloned_repo_path"],
                    "workspace_subdir": workspace_subdir,
                }
            )

    return local_sources


def _is_localhost_host(host: str) -> bool:
    host_lower = host.lower().strip("[]")

    if host_lower in ("localhost", "0.0.0.0", "::1"):  # nosec B104
        return True

    try:
        ip = ipaddress.ip_address(host_lower)
        if isinstance(ip, ipaddress.IPv4Address):
            return ip.is_loopback  # 127.0.0.0/8
        if isinstance(ip, ipaddress.IPv6Address):
            return ip.is_loopback  # ::1
    except ValueError:
        pass

    return False


def rewrite_localhost_targets(targets_info: list[dict[str, Any]], host_gateway: str) -> None:
    from yarl import URL  # type: ignore[import-not-found]

    for target_info in targets_info:
        target_type = target_info.get("type")
        details = target_info.get("details", {})

        if target_type == "web_application":
            target_url = details.get("target_url", "")
            try:
                url = URL(target_url)
            except (ValueError, TypeError):
                continue

            if url.host and _is_localhost_host(url.host):
                details["target_url"] = str(url.with_host(host_gateway))

        elif target_type == "ip_address":
            target_ip = details.get("target_ip", "")
            if target_ip and _is_localhost_host(target_ip):
                details["target_ip"] = host_gateway


# 仓库工具
def clone_repository(repo_url: str, run_name: str, dest_name: str | None = None) -> str:
    console = Console()

    git_executable = shutil.which("git")
    if git_executable is None:
        raise FileNotFoundError("在 PATH 中未找到 Git 可执行文件")

    temp_dir = Path(tempfile.gettempdir()) / "ulrattack_repos" / run_name
    temp_dir.mkdir(parents=True, exist_ok=True)

    if dest_name:
        repo_name = dest_name
    else:
        repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name

    clone_path = temp_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    try:
        with console.status(f"[bold #00d4ff]正在克隆仓库 {repo_url}...", spinner="dots"):
            subprocess.run(  # noqa: S603
                [
                    git_executable,
                    "clone",
                    repo_url,
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

        return str(clone_path.absolute())

    except subprocess.CalledProcessError as e:
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("仓库克隆失败", style="bold #ff0040")
        error_text.append("\n\n", style="white")
        error_text.append(f"无法克隆仓库: {repo_url}\n", style="white")
        error_text.append(
            f"错误: {e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}", style="dim #ff0040"
        )

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 克隆错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    except FileNotFoundError:
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("未找到 GIT", style="bold #ff0040")
        error_text.append("\n\n", style="white")
        error_text.append("Git 未安装或不在 PATH 中.\n", style="white")
        error_text.append("请安装 Git 以克隆仓库.\n", style="white")

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 克隆错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


# Docker 工具
def check_docker_connection() -> Any:
    try:
        return docker.from_env()
    except DockerException:
        console = Console()
        error_text = Text()
        error_text.append("❌ ", style="bold #ff0040")
        error_text.append("DOCKER 不可用", style="bold #ff0040")
        error_text.append("\n\n", style="white")
        error_text.append("无法连接到 Docker 守护进程.\n", style="white")
        error_text.append(
            "请确保 Docker Desktop 已安装并正在运行，然后重试.\n",
            style="white",
        )

        panel = Panel(
            error_text,
            title="[bold #ff0040]🛡️  ULRATTACK 启动错误",
            title_align="center",
            border_style="#ff0040",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        raise RuntimeError("Docker 不可用") from None


def image_exists(client: Any, image_name: str) -> bool:
    try:
        client.images.get(image_name)
    except ImageNotFound:
        return False
    else:
        return True


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    if "Pull complete" in layer_status or "Already exists" in layer_status:
        layers_info[layer_id] = "✓"
    elif "Downloading" in layer_status:
        layers_info[layer_id] = "↓"
    elif "Extracting" in layer_status:
        layers_info[layer_id] = "📦"
    elif "Waiting" in layer_status:
        layers_info[layer_id] = "⏳"
    else:
        layers_info[layer_id] = "•"


def process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        update_layer_status(layers_info, layer_id, line["status"])

        completed = sum(1 for v in layers_info.values() if v == "✓")
        total = len(layers_info)

        if total > 0:
            update_msg = f"[bold #00d4ff]进度: {completed}/{total} 层完成"
            if update_msg != last_update:
                status.update(update_msg)
                return update_msg

    elif "status" in line and "id" not in line:
        global_status = line["status"]
        if "Pulling from" in global_status:
            status.update("[bold #00d4ff]正在获取镜像清单...")
        elif "Digest:" in global_status:
            status.update("[bold #00d4ff]正在验证镜像...")
        elif "Status:" in global_status:
            status.update("[bold #00d4ff]正在完成...")

    return last_update


# LLM 工具
def validate_llm_response(response: Any) -> None:
    if not response or not response.choices or not response.choices[0].message.content:
        raise RuntimeError("LLM 返回无效响应")
