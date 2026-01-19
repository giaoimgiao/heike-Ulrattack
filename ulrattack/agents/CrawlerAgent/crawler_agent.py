from typing import Any

from ulrattack.agents.base_agent import BaseAgent
from ulrattack.llm.config import LLMConfig


class CrawlerAgent(BaseAgent):
    """网络爬虫 Agent - 根据用户需求进行智能网络爬取、Cookie分析和代码生成"""
    
    max_iterations = 300  # 增加迭代次数以支持更复杂的爬取任务

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    async def execute_crawl(self, crawl_config: dict[str, Any]) -> dict[str, Any]:
        """执行网络爬虫任务"""
        user_instructions = crawl_config.get("user_instructions", "")
        crawl_requirement = crawl_config.get("crawl_requirement", "")  # 用户的爬取需求
        targets = crawl_config.get("targets", [])
        
        # 爬虫配置选项
        depth = crawl_config.get("depth", 3)  # 爬取深度
        follow_external = crawl_config.get("follow_external", False)  # 是否跟踪外部链接
        output_format = crawl_config.get("output_format", "json")  # 输出格式
        extract_cookies = crawl_config.get("extract_cookies", True)  # 是否提取 Cookie
        generate_code = crawl_config.get("generate_code", True)  # 是否生成访问代码

        urls = []
        for target in targets:
            target_type = target["type"]
            details = target["details"]

            if target_type == "web_application":
                urls.append(details["target_url"])

        task_parts = ["[网络爬虫模式] 执行智能网络爬取任务："]

        if crawl_requirement:
            task_parts.append(f"\n\n**用户爬取需求：**\n{crawl_requirement}")

        if urls:
            task_parts.append("\n\n**目标URL：**")
            task_parts.extend(f"- {url}" for url in urls)

        task_parts.append(f"\n\n**爬取配置：**")
        task_parts.append(f"- 爬取深度: {depth}")
        task_parts.append(f"- 跟踪外部链接: {'是' if follow_external else '否'}")
        task_parts.append(f"- 输出格式: {output_format}")
        task_parts.append(f"- 提取 Cookie: {'是' if extract_cookies else '否'}")
        task_parts.append(f"- 生成访问代码: {'是' if generate_code else '否'}")
        
        # 强调输出目录和最终任务
        task_parts.append("\n\n**重要输出要求：**")
        task_parts.append("1. 所有爬取结果必须保存到 /workspace/ulrattack_runs/ 目录")
        task_parts.append("2. 如果提取了 Cookie，必须生成 cookies.json 文件")
        task_parts.append("3. 必须创建 Code Generator Agent 生成 access_client.py 访问代码")
        task_parts.append("4. 生成的代码必须能够直接使用爬取的 Cookie 访问目标")
        
        # 针对 LLM 和生图服务的特别说明
        if any(keyword in crawl_requirement.lower() for keyword in ['llm', 'chatgpt', 'claude', 'gemini', 'ai', '大模型', '生图', 'midjourney', 'dalle', 'stable diffusion']):
            task_parts.append("\n\n**AI 服务爬取特别说明：**")
            task_parts.append("- 重点提取认证 Cookie 和 Token")
            task_parts.append("- 分析 API 端点和调用方式")
            task_parts.append("- 生成能调用 AI 服务的代码")
            task_parts.append("- 记录 Token 刷新机制")

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nAdditional instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
