#!/usr/bin/env python3
"""
Compile and run CodeQL queries on CodeQL databases for a specific language.

Requires that CodeQL is installed or available under the CODEQL path.
By default, it compiles all .ql files under 'data/queries/<LANG>/tools' and
'data/queries/<LANG>/issues', then runs them on each CodeQL database located
in 'output/databases/<LANG>'.

Example:
    python src/codeql/run_codeql_queries.py
"""

import subprocess
import os
import sys

# Add project root to sys.path so we can import from 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

# Make sure your common_functions module is in your PYTHONPATH or same folder
from src.utils.common_functions import get_all_dbs
from src.utils.config import get_codeql_path
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Default locations/values
DEFAULT_CODEQL = get_codeql_path()
DEFAULT_LANG = "c"  # Mapped to data/queries/cpp for some tasks


def pre_compile_ql(file_name: str, threads: int, codeql_bin: str) -> None:
    """
    Pre-compile a single .ql file using CodeQL.
    对单个 .ql 查询文件进行预编译。
    预编译会将 .ql 源码转换为 .qlx (编译后的查询)，后续运行时加载速度更快。

    Args:
        file_name (str): The path to the .ql query file.
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    # 检查是否已经存在对应的编译产物 (.qlx 文件)
    # 只有当不存在时才执行编译，避免重复工作
    if not os.path.exists(file_name + "x"):
        subprocess.run(
            [
                codeql_bin,
                "query",
                "compile",
                file_name,
                f'--threads={threads}',
                "--precompile" # 显式告诉 CodeQL 只编译不运行，生成 .qlx 文件
            ],
            check=True,                 # 如果编译命令返回非零退出码，抛出异常
            text=True,                  # 将输入输出作为文本处理
            stdout=subprocess.DEVNULL,  # 屏蔽标准输出，保持控制台清爽
            stderr=subprocess.DEVNULL   # 屏蔽错误输出
        )


def compile_all_queries(queries_folder: str, threads: int, codeql_bin: str) -> None:
    """
    Recursively pre-compile all .ql files in a folder.
    递归地预编译指定目录下的所有 .ql 查询文件。

    Args:
        queries_folder (str): Directory containing .ql files (and possibly subdirectories).
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    # 使用 os.walk 遍历目录树，包括所有子目录
    for subdir, dirs, files in os.walk(queries_folder):
        for file in files:
            # 筛选出扩展名为 .ql 的文件（忽略大小写）
            if os.path.splitext(file)[1].lower() == ".ql":
                file_path = os.path.join(subdir, file)
                # 调用之前的单文件编译函数
                pre_compile_ql(file_path, threads, codeql_bin)


def run_one_query(
    query_file: str,
    curr_db: str,
    output_bqrs: str,
    output_csv: str,
    threads: int,
    codeql_bin: str
) -> None:
    """
    Execute a single CodeQL query on a specific database and export the results.
    执行单个 CodeQL 查询，并将结果导出为 CSV 格式。
    流程：运行查询 -> 生成 BQRS (二进制) -> 解码 BQRS -> 生成 CSV (文本)。

    Args:
        query_file (str): The path to the .ql file to run.
        curr_db (str): The path to the CodeQL database on which to run queries.
        output_bqrs (str): Where to write the intermediate BQRS output.
        output_csv (str): Where to write the CSV representation of the results.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
    """
    # Run the query
    # 第一步：运行查询
    # `codeql query run` 命令会执行 .ql 脚本，并生成一个 BQRS (Binary Query Result Set) 文件
    # 这是一个高效的二进制中间格式，包含所有查询匹配结果
    subprocess.run(
        [
            codeql_bin, "query", "run", query_file,
            f'--database={curr_db}',
            f'--output={output_bqrs}',
            f'--threads={threads}'
        ],
        check=True,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Decode BQRS to CSV
    # 第二步：格式转换
    # 使用 `codeql bqrs decode` 命令将二进制结果转换为人类可读的 CSV 格式
    # 这样我们的 Python 脚本（以及后续的 AI 分析器）就可以轻松读取和解析结果了
    subprocess.run(
        [
            codeql_bin, "bqrs", "decode", output_bqrs,
            '--format=csv', f'--output={output_csv}'
        ],
        check=True,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def run_queries_on_db(
    curr_db: str,
    tools_folder: str,
    queries_folder: str,
    threads: int,
    codeql_bin: str,
    timeout: int = 300
) -> None:
    """
    Execute all tool queries in 'tools_folder' individually on a given database,
    then run a bulk 'database analyze' with all queries in 'queries_folder'.
    针对指定的 CodeQL 数据库执行两类查询任务：
    1. 工具查询 (Tools)：逐个执行，用于提取代码元数据（如函数树、宏定义等），结果分别保存。
    2. 漏洞查询 (Issues)：批量执行，用于扫描安全漏洞，结果汇总到一个 CSV 文件。

    Args:
        curr_db (str): The path to the CodeQL database.
        tools_folder (str): Folder containing individual .ql files to run.
        queries_folder (str): Folder containing .ql queries for bulk analysis.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
        timeout (int, optional): Timeout in seconds for the bulk 'database analyze'.
            Defaults to 300.
    """
    # 1) Run each .ql in tools_folder individually
    # 第一阶段：运行工具类查询
    # 这些查询通常比较轻量，但需要单独处理输出文件，所以采用逐个文件循环的方式
    if os.path.isdir(tools_folder):
        for file in os.listdir(tools_folder):
            if os.path.splitext(file)[1].lower() == ".ql":
                # 调用 run_one_query 封装函数
                # 它会负责：执行查询 -> 生成 BQRS -> 解码为 CSV
                # 输出文件直接保存在数据库目录下，文件名与查询文件名一致
                run_one_query(
                    os.path.join(tools_folder, file),
                    curr_db,
                    os.path.join(curr_db, os.path.splitext(file)[0] + ".bqrs"),
                    os.path.join(curr_db, os.path.splitext(file)[0] + ".csv"),
                    threads,
                    codeql_bin
                )
    else:
        logger.warning("Tools folder '%s' not found. Skipping individual queries.", tools_folder)

    # 2) Run the entire queries folder in one go (bulk analysis)
    # 第二阶段：批量运行漏洞扫描查询
    # 这里直接使用 `codeql database analyze` 命令，它可以一次性接受一个文件夹作为输入
    # CodeQL 会自动并行执行文件夹内的所有查询，并将结果汇总
    if os.path.isdir(queries_folder):
        subprocess.run(
            [
                codeql_bin,
                "database",
                "analyze",
                curr_db,
                queries_folder,         # 传入目录，批量分析
                f'--timeout={timeout}', # 设置超时时间，防止某些复杂查询导致死锁
                '--format=csv',         # 指定输出格式为 CSV
                f'--output={os.path.join(curr_db, "issues.csv")}', # 所有漏洞结果汇总到 issues.csv
                f'--threads={threads}'
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        logger.warning("Queries folder '%s' not found. Skipping bulk analysis.", queries_folder)


def compile_and_run_codeql_queries(
    codeql_bin: str = DEFAULT_CODEQL,
    lang: str = DEFAULT_LANG,
    threads: int = 16,
    timeout: int = 300
) -> None:
    """
    Compile and run CodeQL queries on CodeQL databases for a specific language.
    主入口函数：负责协调 CodeQL 查询的编译与执行全流程。

    1. Pre-compile all .ql files in the tools and queries folders.
    2. Enumerate all CodeQL DBs for the given language.
    3. Run each DB against both the 'tools' and 'issues' queries folders.
    1. 预编译 'tools' 和 'issues' 目录下的所有 .ql 文件。
    2. 枚举指定语言的所有 CodeQL 数据库。
    3. 对每个数据库运行 'tools' (基础信息提取) 和 'issues' (漏洞扫描) 两组查询。

    Args:
        codeql_bin (str, optional): Full path to the 'codeql' executable. Defaults to DEFAULT_CODEQL.
        lang (str, optional): Language code. Defaults to 'c' (which maps to data/queries/cpp).
        threads (int, optional): Number of threads for compilation/execution. Defaults to 16.
        timeout (int, optional): Timeout in seconds for bulk analysis. Defaults to 300.
    """
    # Setup paths
    # 路径映射：将用户输入的 'c' 语言映射到 CodeQL 实际使用的 'cpp' 目录
    queries_subfolder = "cpp" if lang == "c" else lang
    queries_folder = os.path.join("data/queries", queries_subfolder, "issues") # 漏洞查询脚本目录
    tools_folder = os.path.join("data/queries", queries_subfolder, "tools")    # 工具类查询脚本目录
    dbs_folder = os.path.join("output/databases", lang)                        # 待扫描的数据库根目录

    # Step 1: Pre-compile all queries
    # 第一步：预编译所有查询脚本，生成 .qlx 中间文件以加速后续执行
    compile_all_queries(tools_folder, threads, codeql_bin)
    compile_all_queries(queries_folder, threads, codeql_bin)

    # Step 2: List databases and run queries
    # 第二步：遍历并处理所有数据库
    logger.info("Running queries on each DB in %s", dbs_folder)
    
    # List what's in the folder for debugging
    # 调试信息：打印数据库目录下的内容，方便排查空目录问题
    try:
        contents = os.listdir(dbs_folder)
        if len(contents) == 0:
            logger.warning("Database folder '%s' is empty. No databases to process.", dbs_folder)
            return
        logger.debug("Found %d item(s) in database folder: %s", len(contents), contents)
    except OSError as e:
        logger.warning("Cannot access database folder '%s': %s. No databases to process.", dbs_folder, e)
        return
    
    # 使用工具函数获取所有有效的 CodeQL 数据库路径列表
    # 注意：CodeQL 数据库是一个包含 codeql-database.yml 的特定目录结构，不仅仅是文件夹
    dbs_path = get_all_dbs(dbs_folder)
    
    if len(dbs_path) == 0:
        logger.warning("No valid databases found in '%s'. Expected structure: <dbs_folder>/<repo_name>/<db_name>/codeql-database.yml", dbs_folder)
        logger.warning("Make sure databases were downloaded and extracted successfully.")
        return
    
    for curr_db in dbs_path:
        logger.info("Processing DB: %s", curr_db)
        
        # Check if database folder is empty
        # 防御性检查：跳过空文件夹
        if os.path.isdir(curr_db):
            try:
                if len(os.listdir(curr_db)) == 0:
                    logger.warning("Database folder '%s' is empty. Skipping queries.", curr_db)
                    continue
            except OSError:
                logger.warning("Cannot access database folder '%s'. Skipping.", curr_db)
                continue
        
        # If issues.csv was not generated yet, or FunctionTree.csv missing, run
        # 增量扫描逻辑：
        # 仅当 output 文件 (FunctionTree.csv 或 issues.csv) 不存在时才运行查询
        # 这允许我们在中断后重新运行脚本，自动跳过已完成的数据库
        if (not os.path.exists(os.path.join(curr_db, "FunctionTree.csv")) or
                not os.path.exists(os.path.join(curr_db, "issues.csv"))):
            run_queries_on_db(
                curr_db,
                tools_folder,
                queries_folder,
                threads,
                codeql_bin,
                timeout
            )
        else:
            logger.info("Output files already exist for this DB, skipping...")

    logger.info("All databases processed.")


def main_cli() -> None:
    """
    CLI entry point for running codeql queries with defaults.
    """
    compile_and_run_codeql_queries(
        codeql_bin=DEFAULT_CODEQL,
        lang=DEFAULT_LANG,
        threads=16,
        timeout=300
    )


if __name__ == '__main__':
    # Initialize logging
    from src.utils.logger import setup_logging
    setup_logging()
    
    main_cli()
