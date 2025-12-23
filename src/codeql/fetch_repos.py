#!/usr/bin/env python3
"""
Fetch repositories and their CodeQL databases from GitHub.

Allows either:
  1) Bulk retrieval of repositories by language, or
  2) Downloading a specific repository's CodeQL database.

Example CLI usage:
    python fetch_repos.py
    # Or
    python fetch_repos.py myOrgName/myRepoName
"""

import os
import sys

# Add project root to sys.path so we can import from 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import json
import time
import zipfile
import requests
from typing import Any, Dict, List
from pySmartDL import SmartDL

# Import from your local common_functions where needed
from src.utils.common_functions import read_file, write_file_text
from src.utils.config import get_github_token
from src.utils.logger import get_logger

logger = get_logger(__name__)

LANG: str = "c"


def fetch_repos_from_github_api(url: str) -> Dict[str, Any]:
    """
    Make a GET request to GitHub's API with optional rate-limit handling.
    向 GitHub API 发送 GET 请求，并包含可选的速率限制处理。

    Args:
        url (str): The URL to be requested.

    Returns:
        Dict[str, Any]: JSON response from the GitHub API as a Python dict.
    """
    headers: Dict[str, str] = {}
    # 获取 GitHub Token (如果有配置)
    token = get_github_token()
    if token:
        # 如果存在 Token，添加到 Authorization 头中以提高请求限额
        headers["Authorization"] = f'token {token}'

    # 发送 HTTP GET 请求
    response = requests.get(url, headers=headers)
    # 从响应头中获取剩余请求次数
    remaining_requests = response.headers.get("X-RateLimit-Remaining")
    # 从响应头中获取速率限制重置时间戳
    reset_time = response.headers.get("X-RateLimit-Reset")

    # If approaching the rate limit, wait until reset
    # 如果接近速率限制（剩余请求次数小于 7 次），则进入等待逻辑
    if remaining_requests and reset_time and int(remaining_requests) < 7:
        logger.warning("Remaining requests: %s", remaining_requests)
        logger.warning(
            "Rate limit resets at: %s",
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(reset_time)))
        )
        # 计算需要等待的秒数
        wait_time = int(reset_time) - int(time.time())
        if wait_time > 0:
            logger.warning("Waiting for %.2f minutes until the rate limit resets.", wait_time / 60)
            # 休眠直到速率限制重置（额外多等 1 秒以确保安全）
            time.sleep(wait_time + 1)
        # 如果剩余次数已经耗尽（为 0），则递归调用自身重试请求
        if int(remaining_requests) == 0:
            return fetch_repos_from_github_api(url)

    # 返回解析后的 JSON 数据
    return response.json()


def parse_github_search_result(url: str) -> List[Dict[str, Any]]:
    """
    Retrieve repository information from GitHub search results.
    从 GitHub 搜索结果中解析并提取仓库信息。

    Args:
        url (str): The GitHub API search endpoint URL.

    Returns:
        List[Dict[str, Any]]: A list of repository metadata dictionaries.
    """
    # 调用之前定义的 API 函数获取搜索结果页面（JSON 格式）
    page = fetch_repos_from_github_api(url)
    repos = []
    # 遍历搜索结果中的每一个仓库项目 ('items' 列表)
    for item in page.get("items", []):
        repos.append(
            {
                "html_url": item["html_url"],     # 仓库的 Web 页面链接
                "repo_name": item["full_name"],   # 仓库全名 (格式: 组织名/仓库名)
                "forks": item["forks"],           # Fork 数量
                "stars": item["watchers"],        # Star 数量 (GitHub API 中 watchers 对应 stars)
            }
        )
    return repos


def validate_rate_limit(threads: int) -> None:
    """
    Check the GitHub rate limit and, if necessary, pause execution
    until the rate limit resets.
    主动查询 GitHub API 速率限制状态。如果剩余额度不足，则暂停程序执行直到重置。

    Args:
        threads (int): Number of download threads planned; used to estimate
            how many requests might be made.
    """
    # 专门调用速率限制接口查询当前状态 (不消耗核心 API 配额)
    rate_limit = requests.get("https://api.github.com/rate_limit").json()
    remaining_requests = rate_limit["resources"]["core"]["remaining"]
    reset_time = rate_limit["resources"]["core"]["reset"]
    
    # 预估安全阈值：如果剩余请求次数小于 (线程数 + 3)，认为风险过高
    # "+3" 是一个缓冲值，防止多线程并发时瞬间超额
    if int(remaining_requests) < threads + 3:
        logger.warning("Remaining requests: %s", remaining_requests)
        logger.warning(
            "Rate limit resets at: %s",
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(reset_time)))
        )
        # 计算等待时间，并额外增加 120 秒（2分钟）作为安全缓冲
        wait_time = int(reset_time) - int(time.time()) + 120
        if wait_time > 0:
            logger.warning("Waiting for %.2f minutes until the rate limit resets.", wait_time / 60)
            # 挂起程序，直到限流解除
            time.sleep(wait_time)


def custom_download(url: str, local_filename: str) -> None:
    """
    Download a file from GitHub (with optional resume).
    自定义下载函数，支持断点续传和可视化进度条。

    Args:
        url (str): The direct download URL.
        local_filename (str): The path where the file will be saved.
    """
    file_size = 0
    # 检查本地文件是否存在，如果存在则获取其大小，以便进行断点续传
    if os.path.exists(local_filename):
        file_size = os.path.getsize(local_filename)

    headers = {"Accept": "application/zip"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    # 如果本地已有部分文件，通过 Range 头告诉服务器从指定字节开始传输
    if file_size > 0:
        headers["Range"] = f"bytes={file_size}-"

    start_time = time.time()

    try:
        # stream=True 允许我们逐步读取响应内容，而不是一次性加载到内存
        with requests.get(url, headers=headers, stream=True) as response:
            # 计算总大小：本次请求的内容长度 + 之前已下载的长度
            total_size = int(response.headers.get("content-length", 0)) + file_size
            logger.debug("File size: %d KB (%.2f MB)", total_size, total_size / 1_000_000)

            # 如果是断点续传，使用追加模式 'ab'；否则使用覆盖写入模式 'wb'
            mode = "ab" if file_size > 0 else "wb"
            with open(local_filename, mode) as file:
                downloaded_size = file_size
                last_update = time.time()
                
                # 分块读取数据，每块 8KB
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # 为了避免刷新过快导致终端闪烁，每 0.1 秒更新一次进度条
                        current_time = time.time()
                        if current_time - last_update >= 0.1 or downloaded_size == total_size:
                            progress = (downloaded_size / total_size) * 100 if total_size > 0 else 0
                            elapsed = current_time - start_time
                            speed = downloaded_size / elapsed if elapsed > 0 else 0
                            
                            # 格式化显示单位 (MB)
                            downloaded_mb = downloaded_size / 1_000_000
                            total_mb = total_size / 1_000_000
                            speed_mb = speed / 1_000_000
                            
                            # 绘制进度条 (长度 20 字符)
                            bar_length = 20
                            filled = int(bar_length * progress / 100)
                            bar = "█" * filled + "░" * (bar_length - filled)
                            
                            # 实时打印进度信息 (\r 确保在同一行刷新)
                            print(f"\rDownloading: [{bar}] {progress:.1f}% | {downloaded_mb:.2f}/{total_mb:.2f} MB | {speed_mb:.2f} MB/s", end="", flush=True)
                            last_update = current_time
                
                # 下载完成后换行
                print()

        end_time = time.time()
        time_taken = end_time - start_time
        logger.info("File downloaded successfully as %s", local_filename)
        logger.info("Download completed in %.2f minutes.", time_taken / 60)
    except Exception as e:
        logger.warning("Download interrupted: %s. Retrying...", e)
        # 如果下载过程中出现异常（如网络中断），递归调用自身进行重试
        custom_download(url, local_filename)


def multi_thread_db_download(url: str, repo_name: str, threads: int = 2) -> str:
    """
    Download a CodeQL DB .zip file with multiple threads (if no token),
    or via custom_download (if using a token).
    下载 CodeQL 数据库压缩包。
    策略：如果有 GitHub Token，使用单线程断点续传（更稳定且鉴权简单）；
    如果没有 Token，尝试使用多线程下载器 (SmartDL) 提速。

    Args:
        url (str): The direct download URL.
        repo_name (str): The repository name used for constructing the .zip path.
        threads (int, optional): Number of threads for parallel download. Defaults to 2.

    Returns:
        str: The local file system path to the downloaded .zip.
    """
    # 构造保存路径: output/zip_dbs/<语言>/<仓库名>.zip
    dest_dir = os.path.join("output/zip_dbs", LANG)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, repo_name + ".zip")

    request_args = {"headers": {"Accept": "application/zip"}}

    token = get_github_token()
    if token:
        # 策略分支 A：已登录用户
        # 如果配置了 Token，我们优先使用自己实现的 custom_download
        # 原因：SmartDL 库对自定义鉴权头的支持可能不如 requests 灵活，且断点续传逻辑我们已自行控制
        custom_download(url, dest)
        return dest

    # 策略分支 B：未登录用户（匿名下载）
    # 在启动多线程下载前，必须检查速率限制，防止瞬间耗尽匿名额度
    validate_rate_limit(threads)
    
    # 使用 pySmartDL 库进行多线程并发下载，试图最大化带宽利用率
    # verify=False 关闭了 SSL 证书验证（在某些企业内网或代理环境下有助于避免报错）
    downloader = SmartDL(
        url, dest, request_args=request_args, threads=threads, progress_bar=False, verify=False
    )
    downloader.start()
    return downloader.get_dest()


def unzip_file(zip_path: str, extract_to: str) -> None:
    """
    Unzip the specified .zip file into the target directory.

    Args:
        zip_path (str): The path to the .zip file.
        extract_to (str): Directory path where files will be extracted.
    """
    os.makedirs(extract_to, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)


def filter_repos_by_db_and_lang(repos: List[Dict[str, Any]], lang: str) -> List[Dict[str, Any]]:
    """
    For each repo, fetch available CodeQL databases from the GitHub API.
    筛选并匹配：对于给定的仓库列表，查询它们是否包含指定语言的 CodeQL 数据库。

    Args:
        repos (List[Dict[str, Any]]): A list of repository info dictionaries.
        lang (str): The language of interest (e.g., "c", "cpp").

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing DB info
            for the matching language.
    """
    repos_db = []
    # 语言映射处理：GitHub CodeQL 通常将 C 和 C++ 统一标记为 "cpp"
    # 因此如果用户搜索 "c"，我们需要将其转换为 "cpp" 以匹配 API 返回结果
    gh_lang = "cpp" if lang == "c" else lang

    for repo in repos:
        # 调用 GitHub API 查询该仓库下所有可用的 CodeQL 数据库列表
        # 这是一个隐藏较深的 API 端点：/repos/{owner}/{repo}/code-scanning/codeql/databases
        db_info = fetch_repos_from_github_api(
            f"https://api.github.com/repos/{repo['repo_name']}/code-scanning/codeql/databases"
        )
        
        # 遍历该仓库拥有的所有数据库（可能包含 java, python, cpp 等多个）
        for db in db_info:
            # 只有当数据库语言与我们目标语言一致时，才将其加入结果列表
            if "language" in db and db["language"] == gh_lang:
                repos_db.append(
                    {
                        "repo_name": repo["repo_name"],
                        "html_url": repo["html_url"],
                        "content_type": db["content_type"], # 例如: application/zip
                        "size": db["size"],                 # 数据库文件大小（字节）
                        "db_url": db["url"],                # 数据库下载链接
                        "forks": repo["forks"],
                        "stars": repo["stars"],
                    }
                )

    print(f"[REPO_DB]  Repo DB :\n {repos_db}")
    return repos_db
   


def search_top_matching_repos(max_repos: int, lang: str) -> List[Dict[str, Any]]:
    """
    Gather a list of repositories (sorted by stars) and retrieve
    their CodeQL DB info for the specified language.

    Args:
        max_repos (int): Number of repositories to stop after collecting.
        lang (str): The programming language for which to search
            (e.g., "c" or "cpp").

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing each repo's DB info.
    """
    repos_db: List[Dict[str, Any]] = []
    curr_page = 1

    while len(repos_db) < max_repos:
        # Search for top-starred repos by language
        search_url = (
            f"https://api.github.com/search/repositories"
            f"?q=language:{lang}&sort=stars&order=desc&page={curr_page}"
        )
        all_repos = parse_github_search_result(search_url)

        db_in_page = filter_repos_by_db_and_lang(all_repos, lang)
        repos_db += db_in_page

        curr_page += 1

    return repos_db[:max_repos]


def download_and_extract_db(repo: Dict[str, Any], threads: int, extract_folder: str) -> None:
    """
    Handle the download and extraction of a single repository's CodeQL DB.
    处理单个仓库 CodeQL 数据库的下载、解压及后续的文件结构整理。

    Args:
        repo (Dict[str, Any]): The repository DB info dictionary.
        threads (int): Number of threads for multi-threaded download.
        extract_folder (str): Where to extract the DB files.
    """
    org_name, repo_name = repo["repo_name"].split("/")

    print(f"[DOWNLOAD]  Downloading repo {org_name}/{repo_name} from {repo['db_url']}")

    
    logger.info("Downloading repo %s/%s", org_name, repo_name)
    # 步骤 1: 调用多线程下载器获取 .zip 文件
    zip_path = multi_thread_db_download(repo["db_url"], repo_name, threads)

    # 步骤 2: 解压缩
    db_path = os.path.join(extract_folder, repo_name)
    unzip_file(zip_path, db_path)
    # 关键点: 解压后稍微等待一下，让操作系统文件系统缓冲区同步，避免立即操作文件时出现“文件被占用”错误
    time.sleep(1)  # Let file system sync

    # 步骤 3: 目录结构标准化 (重命名)
    # CodeQL 数据库解压后的内部结构可能不统一（有时叫 'codeql_db'，有时直接是语言名 'c'/'cpp'）
    # 我们需要将其统一重命名为仓库名，方便后续工具调用
    source_path = None
    target_path = os.path.join(db_path, repo_name)
    
    # 自动探测实际的数据库根目录名称
    if os.path.exists(os.path.join(db_path, "codeql_db")):
        source_path = os.path.join(db_path, "codeql_db")
    elif os.path.exists(os.path.join(db_path, LANG)):
        source_path = os.path.join(db_path, LANG)
    
    if source_path and not os.path.exists(target_path):
        # 针对 Windows 系统的健壮性处理：
        # Windows 的文件锁机制比较激进（如杀毒软件扫描、索引服务），可能导致 os.rename 失败
        # 这里实现了指数退避重试机制 (Exponential Backoff)
        for attempt in range(3):
            try:
                time.sleep(0.5 * (attempt + 1))  # 逐步增加等待时间: 0.5s -> 1s -> 1.5s
                os.rename(source_path, target_path)
                break
            except (PermissionError, OSError):
                if attempt == 2:  # 如果 3 次尝试都失败，则抛出致命错误
                    logger.error("❌ Error: Could not rename %s", source_path)
                    logger.error("   The folder may be locked. Please close any IDEs, File Explorer, or antivirus")
                    logger.error("   that might be accessing this folder, then run the script again.")
                    sys.exit(1)

def download_db_by_name(repo_name: str, lang: str, threads: int) -> None:
    """
    Download the CodeQL database for a single repository.
    针对指定的单个仓库（格式 'org/repo'）下载其 CodeQL 数据库。
    适用于手动指定下载某个特定项目，而非批量爬取 Top N 项目。

    Args:
        repo_name (str): The repository in 'org/repo' format.
        lang (str): The language to pass to GH DB detection (e.g., 'c').
        threads (int): Number of threads to use for download.
    """
    # 构造一个最小化的仓库元数据对象，以适配 filter_repos_by_db_and_lang 函数的输入要求
    # 这里的 stars/forks 设为 0 仅作为占位符，不影响下载逻辑
    repo = {"stars": 0, "forks": 0, "repo_name": repo_name, "html_url": ""}
    
    # 复用之前的过滤逻辑：查询该仓库是否存在指定语言的 DB
    repo_db = filter_repos_by_db_and_lang([repo], lang)
    
    # 如果没找到对应语言的 DB，打印警告并退出
    if not repo_db:
        logger.warning("No %s DB found for %s", lang, repo_name)
        return
        
    # 找到后，调用通用下载解压流程
    download_and_extract_db(repo_db[0], threads, os.path.join("output/databases", lang))


def fetch_codeql_dbs(
    lang: str = "c",
    max_repos: int = 100,
    threads: int = 4,
    single_repo: str = None,
    backup_file: str = "repos_db.json"
) -> None:
    """
    Fetch and download CodeQL databases for GitHub repositories.
    主入口函数：负责协调从 GitHub 抓取和下载 CodeQL 数据库的全流程。

    If `single_repo` is provided (e.g. 'org/repo'), only that DB is downloaded.
    Otherwise, fetch the top repositories for `lang` and retrieve their DBs.
    支持两种模式：
    1. 单个下载模式：指定 `single_repo`。
    2. 批量爬取模式：自动搜索指定语言(`lang`)的 Top N 热门仓库并批量下载。

    Args:
        lang (str, optional): The programming language. Defaults to "c".
        max_repos (int, optional): Max number of top-starred repos to fetch. Defaults to 100.
        threads (int, optional): Number of threads for multi-threaded download. Defaults to 4.
        single_repo (str, optional): If provided, downloads only this repo's DB.
            Format: "org/repo". Defaults to None.
        backup_file (str, optional): Path to the JSON file used to store repo data
            between downloads. Defaults to "repos_db.json".
    """
    # Ensure needed directories exist
    # 初始化输出目录结构：
    # output/databases/c : 存放解压后的数据库
    # output/zip_dbs/c   : 存放原始 zip 压缩包
    db_folder = os.path.join("output/databases", lang)
    os.makedirs(db_folder, exist_ok=True)
    zip_folder = os.path.join("output/zip_dbs", lang)
    os.makedirs(zip_folder, exist_ok=True)

    if single_repo:
        # Download only that specific repository
        # 模式 1：如果指定了单个仓库名，直接走单点下载流程，然后结束
        download_db_by_name(single_repo, lang, threads)
        return

    # Otherwise fetch top repos for this language
    # 模式 2：批量爬取 Top N 仓库
    logger.info("Fetching up to %d top %s repos with DBs on GitHub.", max_repos, lang)
    # 步骤 A: 搜索并筛选出包含有效 DB 的仓库列表
    repos_db = search_top_matching_repos(max_repos, lang)
    # 步骤 B: 立即将待下载列表保存到本地 JSON 文件，防止中途崩溃导致进度丢失
    write_file_text(backup_file, json.dumps(repos_db))

    for i, repo_info in enumerate(repos_db):
        logger.info("Downloading repo %d/%d: %s", i + 1, len(repos_db), repo_info['repo_name'])
        # 步骤 C: 逐个下载并解压
        download_and_extract_db(repo_info, threads, db_folder)

        # Update the backup file in case of error or partial completion
        # 步骤 D: 实时更新备份文件，每下载成功一个，就从列表中移除一个
        # 这样如果程序中断，下次可以读取这个 JSON 继续下载剩余的，实现简单的断点续传
        remaining = repos_db[i + 1 :]
        write_file_text(backup_file, json.dumps(remaining))

    # 全部下载完成后，清理临时备份文件
    if os.path.exists(backup_file):
        os.unlink(backup_file)


def main_cli() -> None:
    """
    CLI entry point. If no arguments, fetch top LANG repos.
    If an argument 'org/repo' is provided, fetch just that DB.
    """
    logger.info("Current lang: %s", LANG)

    if len(sys.argv) == 1:
        # No arguments, do the "bulk fetch"
        fetch_codeql_dbs(lang=LANG, max_repos=100, threads=4)
    else:
        # If a single arg is provided, assume it's an 'org/repo' to fetch
        if "/" in sys.argv[1]:
            fetch_codeql_dbs(lang=LANG, threads=4, single_repo=sys.argv[1])
        else:
            logger.error("Usage:\n  python fetch_repos.py\n  or\n  python fetch_repos.py orgName/repoName")


if __name__ == "__main__":
    main_cli()


# output
# Current lang: c
# [REPO_DB]  Repo DB :
#  [{'repo_name': 'redis/redis', 'html_url': '', 'content_type': 'application/zip', 'size': 29921164, 'db_url': 'https://api.github.com/repositories/156018/code-scanning/codeql/databases/cpp', 'forks': 0, 'stars': 0}]
# [DOWNLOAD]  Downloading repo redis/redis from https://api.github.com/repositories/156018/code-scanning/codeql/databases/cpp
# Downloading repo redis/redis
