"""
工具：保存生成的文件到 ulrattack_runs 目录
类似于 create_vulnerability_report，但用于保存脚本、代码等文件
"""
from typing import Any
from pathlib import Path

from ulrattack.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def save_generated_file(
    filename: str,
    content: str,
    description: str = "",
    subdirectory: str = "",
    agent_state: Any = None,
) -> dict[str, Any]:
    """
    保存生成的文件到宿主机的 ulrattack_runs 目录
    
    Args:
        filename: 文件名（例如：attack_toolkit.py, cookies.json）
        content: 文件内容
        description: 文件描述
        subdirectory: 子目录（例如：exploits, payloads）
        agent_state: Agent 状态（自动传入）
    
    Returns:
        包含成功/失败状态和文件路径的字典
    """
    try:
        from ulrattack.telemetry.tracer import get_global_tracer
        
        tracer = get_global_tracer()
        if not tracer:
            return {
                "success": False,
                "error": "Tracer not available - cannot save file to host machine",
                "path": None,
            }
        
        # 获取运行目录
        run_dir = tracer.get_run_dir()
        
        # 如果指定了子目录，创建它
        if subdirectory:
            target_dir = run_dir / subdirectory
            target_dir.mkdir(parents=True, exist_ok=True)
        else:
            target_dir = run_dir
        
        # 保存文件
        file_path = target_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # 记录到 tracer（可选，用于跟踪生成了哪些文件）
        if not hasattr(tracer, '_generated_files'):
            tracer._generated_files = []
        
        tracer._generated_files.append({
            'filename': filename,
            'path': str(file_path),
            'subdirectory': subdirectory,
            'description': description,
            'size': len(content),
        })
        
        return {
            "success": True,
            "message": f"文件已保存到宿主机: {file_path.relative_to(Path.cwd())}",
            "path": str(file_path.relative_to(Path.cwd())),
            "full_path": str(file_path),
        }
        
    except Exception as e:
        import logging
        logging.exception(f"Failed to save file {filename}")
        
        return {
            "success": False,
            "error": f"保存文件失败: {str(e)}",
            "path": None,
        }

