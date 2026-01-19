from typing import Any

from ulrattack.agents.base_agent import BaseAgent
from ulrattack.llm.config import LLMConfig


class AttackAgent(BaseAgent):
    """攻击测试 Agent - 根据渗透发现的漏洞进行全方位利用并生成攻击脚本"""
    
    max_iterations = 500  # 攻击测试需要更多迭代

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    async def execute_attack(self, attack_config: dict[str, Any]) -> dict[str, Any]:
        """执行攻击测试"""
        user_instructions = attack_config.get("user_instructions", "")
        targets = attack_config.get("targets", [])
        vulnerabilities = attack_config.get("vulnerabilities", [])  # 可选：来自渗透测试的漏洞列表
        
        # 攻击配置选项
        generate_exploits = attack_config.get("generate_exploits", True)  # 是否生成攻击脚本
        generate_report = attack_config.get("generate_report", True)  # 是否生成攻击报告
        post_exploitation = attack_config.get("post_exploitation", True)  # 是否进行后渗透

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = ["[攻击测试模式] 对以下目标执行全方位漏洞利用攻击："]

        if repositories:
            task_parts.append("\n\n**Repositories:**")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\n**Local Codebases:**")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\n**目标 URLs:**")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\n**IP Addresses:**")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        # 如果有已知漏洞，添加到任务描述中
        if vulnerabilities:
            task_parts.append("\n\n**已知漏洞（来自渗透测试）：**")
            for vuln in vulnerabilities:
                task_parts.append(f"- {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'Unknown')})")

        # 攻击配置说明
        task_parts.append("\n\n**攻击配置：**")
        task_parts.append(f"- 生成攻击脚本: {'是' if generate_exploits else '否'}")
        task_parts.append(f"- 生成攻击报告: {'是' if generate_report else '否'}")
        task_parts.append(f"- 执行后渗透: {'是' if post_exploitation else '否'}")
        
        # 强调输出目录和最终任务
        task_parts.append("\n\n**重要输出要求：**")
        task_parts.append("1. 所有攻击脚本和报告必须保存到 /workspace/ulrattack_runs/ 目录")
        task_parts.append("2. 必须创建 Exploit Generator Agent 生成自动化攻击脚本")
        task_parts.append("3. 必须创建 Attack Report Agent 生成攻击报告")
        task_parts.append("4. 生成的脚本必须可以直接运行进行漏洞利用")
        task_parts.append("\n\n**输出文件结构：**")
        task_parts.append("- /workspace/ulrattack_runs/attack_toolkit.py - 综合攻击工具包")
        task_parts.append("- /workspace/ulrattack_runs/exploits/*.py - 各漏洞利用脚本")
        task_parts.append("- /workspace/ulrattack_runs/payloads/*.txt - Payload 文件")
        task_parts.append("- /workspace/ulrattack_runs/attack_report.md - 攻击报告")

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
