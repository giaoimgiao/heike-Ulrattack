import docker
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def clean_ulrattack_containers():
    try:
        client = docker.from_env()
        # 清理所有带有 ulrattack 相关标签或名字的容器
        containers = client.containers.list(all=True)
        ulrattack_containers = [
            c for c in containers 
            if "ulrattack" in c.name or "ulrattack-scan-id" in c.labels or "ulrattack" in str(c.image)
        ]

        if not ulrattack_containers:
            logger.info("未发现残留的 ULRATTACK 容器。")
            return

        logger.info(f"发现 {len(ulrattack_containers)} 个残留容器，正在清理...")

        for container in ulrattack_containers:
            try:
                logger.info(f"正在停止容器: {container.name} ({container.id[:8]})")
                container.stop(timeout=1)
            except Exception as e:
                logger.warning(f"停止容器失败: {e}")
            
            try:
                logger.info(f"正在删除容器: {container.name}")
                container.remove(force=True)
            except Exception as e:
                logger.error(f"删除容器失败: {e}")

        logger.info("清理完成！")

    except Exception as e:
        logger.error(f"连接 Docker 失败: {e}")
        logger.info("请确保 Docker Desktop 正在运行。")

if __name__ == "__main__":
    clean_ulrattack_containers()

