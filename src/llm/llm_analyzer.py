#!/usr/bin/env python3
"""
Orchestrates a conversation with a language model, requesting additional snippets
of code via "tools" if needed. Uses either OpenAI or AzureOpenAI (or placeholder
code for a HuggingFace endpoint) to handle queries.

All logic is now wrapped in the `LLMAnalyzer` class for improved organization.
"""

import os
import sys
import re
import json
import argparse

# Add project root to sys.path so we can import from 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from typing import Any, Dict, List, Optional, Tuple, Union

# Import the relevant LLM clients here
import litellm
from src.utils.llm_config import load_llm_config, get_model_name
from src.utils.config_validator import validate_llm_config_dict
from src.utils.logger import get_logger
from src.utils.common_functions import read_file_lines_from_zip
from src.utils.exceptions import CodeQLError, LLMApiError, LLMConfigError

logger = get_logger(__name__)


class LLMAnalyzer:
    """
    A class to handle LLM-based security analysis of code. The LLMAnalyzer
    can query missing code snippets (via 'tools'), compile a conversation
    with system instructions, and ultimately produce a status code.
    """

    def __init__(self) -> None:
        """
        Initialize the LLMAnalyzer instance and define tools and system messages.
        """
        self.config: Optional[Dict[str, Any]] = None
        self.model: Optional[str] = None

        # Tools configuration: A set of function calls the LLM can invoke
        # 工具配置：定义了一组 LLM 可以调用的函数接口（Function Calling / Tools）
        # 这些工具赋予了 AI "阅读代码" 的能力，使其不再局限于初始提供的代码片段
        self.tools: List[Dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": "Retrieves the code for a missing function code.",
                    # 工具 1：获取函数源码
                    # 当 AI 看到一个函数调用（例如 process_data()）但不知道其内部实现时使用
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {
                                "type": "string",
                                "description": (
                                    "The name of the function to retrieve. In case of a class"
                                    " method, provide ClassName::MethodName."
                                )
                            }
                        },
                        "required": ["function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_caller_function",
                    "description": (
                        "Retrieves the caller function of the function with the issue. "
                        "Call it repeatedly to climb further up the call chain."
                    ),
                    # 工具 2：获取调用者（向上回溯）
                    # 这是进行污点分析（Taint Analysis）的关键。
                    # 如果 AI 发现某个函数的参数有问题，它可以使用此工具查看“是谁把这个脏数据传进来的”，
                    # 从而沿着调用链一步步向上追溯漏洞源头。
                    "parameters": {
                        "type": "object",
                        "properties": {},
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_class",
                    "description": (
                        "Retrieves class / struct / union implementation (anywhere in code). "
                        "If you need a specific method from that class, use get_function_code instead."
                    ),
                    # 工具 3：获取类/结构体定义
                    # C++ 中对象的状态往往存储在成员变量中。要理解某个方法是否安全，
                    # 往往需要查看整个类的定义（包括成员变量和其他 helper 方法）。
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "object_name": {
                                "type": "string",
                                "description": "The name of the class / struct / union."
                            }
                        },
                        "required": ["object_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_global_var",
                    "description": (
                        "Retrieves global variable definition (anywhere in code). "
                        "If it's a variable inside a class, request the class instead."
                    ),
                    # 工具 4：获取全局变量
                    # 在嵌入式或旧式 C 代码中，全局配置或状态变量经常影响程序逻辑。
                    # 此工具帮助 AI 理解那些“凭空出现”的变量是从哪里定义的。
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "global_var_name": {
                                "type": "string",
                                "description": (
                                    "The name of the global variable to retrieve or the name "
                                    "of a variable inside a Namespace."
                                )
                            }
                        },
                        "required": ["global_var_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_macro",
                    "description": "Retrieves a macro definition (anywhere in code).",
                    # 工具 5：获取宏定义
                    # 对于 C/C++ 安全审计至关重要！
                    # 很多看似安全的函数调用（如 SAFE_COPY）实际上可能是一个有问题的宏。
                    # 或者某个常量 MAX_SIZE 到底是多少？不看宏定义根本无法判断是否溢出。
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "macro_name": {
                                "type": "string",
                                "description": "The name of the macro."
                            }
                        },
                        "required": ["macro_name"]
                    }
                }
            }
        ]

        # Base system messages with instructions and guidance for the LLM
        # 核心系统提示词 (System Prompts)：这是 AI 安全审计专家的人设和操作手册。
        # 这些消息会在对话开始时发送给 LLM，用于规范它的行为模式和输出格式。
        self.MESSAGES: List[Dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    "You are an expert security researcher.\n"
                    # 人设定义：你是一名专业的安全研究员。
                    "Your task is to verify if the issue that was found has a real security impact.\n"
                    # 任务目标：验证 CodeQL 扫描出的漏洞是否真的具有安全影响（排除误报）。
                    "Return a concise status code based on the guidelines provided.\n"
                    "Use the tools function when you need code from other parts of the program.\n"
                    # 关键指令：当现有代码不足以判断时，必须使用 Tools 去查阅更多代码，而不是瞎猜。
                    "You *MUST* follow the guidelines!"
                )
            },
            {
                "role": "system",
                "content": (
                    "### Answer Guidelines\n"
                    # 思考链 (Chain of Thought) 强制引导：
                    # 强制 AI 按照固定的步骤进行思考和回答，避免它直接跳到结论。
                    "Your answer must be in the following order!\n"
                    "1. Briefly explain the code.\n"
                    # 步骤 1：先解释代码逻辑，证明它读懂了。
                    "2. Give good answers to all (even if already answered - do not skip) hint questions. "
                    "(Copy the question word for word, then provide the answer.)\n"
                    # 步骤 2：回答预设的引导性问题（Hint Questions），这些问题通常由静态分析工具生成，
                    # 比如“源缓冲区大小是多少？”“目标缓冲区大小是多少？”
                    "3. Do you have all the code needed to answer the questions? If no, use the tools!\n"
                    # 步骤 3：自我反思。如果发现可以回答上面的问题，就继续；如果不行，立即调用工具。
                    "4. Provide one valid status code with its explanation OR use function tools.\n"
                )
            },
            {
                "role": "system",
                "content": (
                    "### Status Codes\n"
                    # 结构化输出协议：使用特定的数字代码来表示最终结论，方便程序解析。
                    "- **1337**: Indicates a security vulnerability. If legitimate, specify the parameters that "
                    "could exploit the issue in minimal words.\n"
                    # 代码 1337 (Leet)：确认是实锤漏洞。必须说明利用条件。
                    "- **1007**: Indicates the code is secure. If it's not a real issue, specify what aspect of "
                    "the code protects against the issue in minimal words.\n"
                    # 代码 1007 (Loot/Safe)：确认是安全的（误报）。必须说明防御机制（如“使用了 safe_copy 宏”）。
                    "- **7331**: Indicates more code is needed to validate security. Write what data you need "
                    "and explain why you can't use the tools to retrieve the missing data, plus add **3713** "
                    "if you're pretty sure it's not a security problem.\n"
                    # 代码 7331：依然信息不足（即使调用了工具也查不到），需要人工介入。
                    "Only one status should be returned!\n"
                    "You will get 10000000000$ if you follow all the instructions and use the tools correctly!"
                    # 激励机制 (Prompt Engineering)：通过虚拟的巨额奖励来提高模型遵循指令的意愿（这在 GPT-4 上被证明有效）。
                )
            },
        ]

    def init_llm_client(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the LLM configuration for LiteLLM.
        初始化 LLM 客户端配置。
        支持两种模式：
        1. 显式传入配置字典（通常用于测试或动态配置）。
        2. 自动从 .env 文件加载配置（默认模式）。

        Args:
            config (Dict, optional): Full configuration dictionary. If not provided, loads from .env file.
        
        Raises:
            LLMConfigError: If configuration is invalid or cannot be loaded.
        """
        try:
            # If config is provided, use it directly
            # 模式 1: 使用传入的配置对象
            if config:
                validate_llm_config_dict(config) # 校验配置完整性
                self.config = config
                # Format model name for LiteLLM (add provider prefix if needed)
                # 格式化模型名称：LiteLLM 通常要求格式为 "provider/model_name"
                # 例如：openai/gpt-4o, anthropic/claude-3
                provider = config.get("provider", "openai")
                model = config.get("model", "gpt-4o")
                self.model = get_model_name(provider, model)
                logger.info("Using model: %s", self.model)
                # 设置环境变量（如 API_KEY），供 LiteLLM 库自动读取
                self.setup_litellm_env()
                return
            
            # Load from .env file
            # 模式 2: 从环境变量 (.env) 加载
            config = load_llm_config() # 这是一个 helper 函数，负责读取 .env 并解析
            validate_llm_config_dict(config)
            self.config = config
            # Model is already formatted by load_llm_config() via get_model_name()
            # 在 load_llm_config 内部已经完成了模型名称的格式化
            self.model = config.get("model", "gpt-4o")
            self.setup_litellm_env()
            
        except ValueError as e:
            # Configuration validation errors should be LLMConfigError
            # 捕获校验错误，并包装为自定义的 LLMConfigError，方便上层统一处理
            raise LLMConfigError(f"Invalid LLM configuration: {e}") from e
        except Exception as e:
            # Other errors (e.g., from load_llm_config) should also be LLMConfigError
            raise LLMConfigError(f"Failed to initialize LLM client: {e}") from e
    
    def setup_litellm_env(self) -> None:
        """
        Set up environment variables for LiteLLM based on config.
        LiteLLM reads from environment variables automatically.
        根据配置自动设置 LiteLLM 所需的环境变量。
        LiteLLM 是一个极其强大的库，它标准化了不同 LLM 供应商的接口，
        但不同供应商需要的环境变量名千奇百怪（如 OPENAI_API_KEY vs AZURE_API_KEY）。
        这个函数的作用就是充当“翻译官”，把统一的 config 字典翻译成各家厂商特定的环境变量。
        """
        if not self.config:
            return
        
        provider = self.config.get("provider", "openai")
        api_key = self.config.get("api_key")
        
        # Mapping table for providers that only need API key set
        # 简单模式厂商映射表：这些厂商只需要一个 API Key 就能工作
        API_KEY_ENV_VARS = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "mistral": "MISTRAL_API_KEY",
            "codestral": "MISTRAL_API_KEY",
            "groq": "GROQ_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "huggingface": "HUGGINGFACE_API_KEY",
            "cohere": "COHERE_API_KEY",
            "gemini": "GOOGLE_API_KEY",
        }
        
        # Handle providers with simple API key mapping
        # 场景 1：处理只需要 API Key 的标准厂商
        if provider in API_KEY_ENV_VARS:
            if api_key:
                os.environ[API_KEY_ENV_VARS[provider]] = api_key
                # 特殊处理：Cohere 有时使用 CO_API_KEY，为了兼容性多设置一个
                if provider == "cohere":
                    os.environ["CO_API_KEY"] = api_key
        
        # Handle Azure (requires endpoint and api_version)
        # 场景 2：处理 Azure OpenAI（微软云）
        # Azure 比较特殊，除了 Key 还需要 Endpoint（资源地址）和 API Version
        elif provider == "azure":
            if api_key:
                os.environ["AZURE_API_KEY"] = api_key
            if self.config.get("endpoint"):
                os.environ["AZURE_API_BASE"] = self.config["endpoint"]
            if self.config.get("api_version"):
                os.environ["AZURE_API_VERSION"] = self.config["api_version"]
        
        # Handle Bedrock (uses AWS credentials)
        # 场景 3：处理 AWS Bedrock（亚马逊云）
        # AWS 使用标准的 Access Key / Secret Key 认证体系，以及 Region（区域）
        elif provider == "bedrock":
            if api_key:
                os.environ["AWS_ACCESS_KEY_ID"] = api_key # 复用 api_key 字段存储 Access Key
            if self.config.get("aws_secret_access_key"):
                os.environ["AWS_SECRET_ACCESS_KEY"] = self.config["aws_secret_access_key"]
            if self.config.get("endpoint"):  # Endpoint contains AWS region
                os.environ["AWS_REGION_NAME"] = self.config["endpoint"]
        
        # Handle Vertex AI (uses GCP credentials)
        # 场景 4：处理 Google Vertex AI
        # Google 通常依赖 GCP 项目 ID 和 Location，认证通常通过 ADC (Application Default Credentials) 自动处理
        elif provider == "vertex_ai":
            if self.config.get("gcp_project_id"):
                os.environ["GCP_PROJECT_ID"] = self.config["gcp_project_id"]
            if self.config.get("gcp_location"):
                os.environ["GCP_LOCATION"] = self.config["gcp_location"]
            # GOOGLE_APPLICATION_CREDENTIALS should be set by user or gcloud auth
        
        # Handle Ollama (uses OLLAMA_BASE_URL)
        # 场景 5：处理 Ollama（本地部署模型）
        # Ollama 只需要指定服务地址（如 http://localhost:11434）
        elif provider == "ollama":
            if self.config.get("endpoint"):
                os.environ["OLLAMA_BASE_URL"] = self.config["endpoint"]
        
        # Generic fallback for future providers that only require an API key
        # 兜底策略：处理未知的新厂商
        # 假设它们遵循 {PROVIDER}_API_KEY 的命名规范
        else:
            if api_key:
                # Use standard LiteLLM convention: {PROVIDER}_API_KEY
                env_var_name = f"{provider.upper()}_API_KEY"
                os.environ[env_var_name] = api_key

    def get_function_by_line(
        self,
        function_tree_file: str,
        file: str,
        line: int
    ) -> Optional[Dict[str, str]]:
        """
        Retrieve the function dictionary from a CSV (FunctionTree.csv) that matches
        the specified file and line coverage.
        根据给定的文件路径和行号，查找该行代码属于哪个函数。
        这是 CodeQL 分析结果反向定位的关键：当我们知道某一行有漏洞（CodeQL 告警），
        我们需要知道它位于哪个函数体内，才能提取出整个函数的代码给 LLM 分析。

        Args:
            function_tree_file (str): Path to the FunctionTree.csv file.
            file (str): Name of the file as it appears in the CSV row.
            line (int): A line number within the function's start_line and end_line range.

        Returns:
            Optional[Dict[str, str]]: The matching function row as a dict, or None if not found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        # CSV 列定义：这必须与 CodeQL 查询生成的 FunctionTree.csv 格式完全一致
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        try:
            with open(function_tree_file, "r", encoding="utf-8") as f:
                while True:
                    # 逐行读取 CSV 文件，避免一次性加载大文件导致内存溢出
                    function = f.readline()
                    if not function:
                        break
                    # 快速过滤：如果这一行不包含目标文件名，直接跳过，提高搜索速度
                    if file in function:
                        # 使用正则拆分 CSV 行，处理可能存在的引号包裹的字段
                        row = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', function)
                        row_dict = dict(zip(keys, row))
                        
                        # 范围检查：判断目标行号 line 是否在当前函数的 [start_line, end_line] 区间内
                        if row_dict and row_dict["start_line"] and row_dict["end_line"]:
                            start = int(row_dict["start_line"])
                            end = int(row_dict["end_line"])
                            if start <= line <= end:
                                return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e
        return None

    def get_function_by_name(
        self,
        function_tree_file: str,
        function_name: str,
        all_function: List[Dict[str, Any]],
        less_strict: bool = False
    ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
        """
        Retrieve a function by searching function_name in FunctionTree.csv.
        If not found, tries partial match if less_strict is True.
        根据函数名查找函数定义。支持精确匹配和模糊匹配。
        此函数不仅仅是查找名字，它还利用了 `all_function` 上下文来加速查找。

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            function_name (str): Desired function name (e.g., 'MyClass::MyFunc').
            all_function (List[Dict[str, Any]]): A list of known function dictionaries.
                这个参数很关键：它包含了我们当前已经“认识”的函数列表。
                算法会优先在这些已知函数的“邻居”（同一个文件或相关联的 ID）中查找，提高效率。
            less_strict (bool, optional): If True, use partial matching. Defaults to False.
                如果为 True，只要包含该名字就算匹配（例如搜 "copy" 能匹配到 "safe_copy"）。

        Returns:
            Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
                - The found function (dict) or an error message (str).
                - The "parent function" that references it, if relevant.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        # 预处理：去掉可能存在的类名前缀，只保留函数名本身
        # 例如 "MyClass::process" -> "process"
        function_name_only = function_name.split("::")[-1]

        # 遍历当前上下文中的已知函数
        for current_function in all_function:
            try:
                with open(function_tree_file, "r", encoding="utf-8") as f:
                    while True:
                        row = f.readline()
                        if not row:
                            break
                        # 优化策略：只检查那些 ID 包含在当前函数上下文中的记录
                        # 这是一个基于 CodeQL 索引结构的优化，假设相关函数在 CSV 中可能具有某种关联性
                        if current_function["function_id"] in row:
                            row_split = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', row)
                            row_dict = dict(zip(keys, row_split))
                            if not row_dict:
                                continue

                            candidate_name = row_dict["function_name"].replace("\"", "")
                            # 匹配逻辑：精确匹配 OR (模糊匹配 AND 开启了模糊模式)
                            if (candidate_name == function_name_only
                                    or (less_strict and function_name_only in candidate_name)):
                                return row_dict, current_function
            except FileNotFoundError as e:
                raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
            except PermissionError as e:
                raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
            except OSError as e:
                raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e

        # Try partial matching if less_strict is False
        if not less_strict:
            return self.get_function_by_name(function_tree_file, function_name, all_function, True)
        else:
            err = (
                f"Function '{function_name}' not found. Make sure you're using "
                "the correct tool and args."
            )
            return err, None

    def get_macro(
        self,
        curr_db: str,
        macro_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return macro info from Macros.csv for the given macro_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to the current CodeQL database folder.
            macro_name (str): Macro name to search for.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with 'macro_name' and 'body' if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Macros CSV file cannot be read (not found, permission denied, etc.).
        """
        macro_file = os.path.join(curr_db, "Macros.csv")
        keys = ["macro_name", "body"]

        try:
            with open(macro_file, "r", encoding='utf-8') as f:
                while True:
                    macro = f.readline()
                    if not macro:
                        break
                    if macro_name in macro:
                        row = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', macro)
                        row_dict = dict(zip(keys, row))
                        if not row_dict:
                            continue

                        actual_name = row_dict["macro_name"].replace("\"", "")
                        if (actual_name == macro_name
                                or (less_strict and macro_name in actual_name)):
                            return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Macros CSV file not found: {macro_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading Macros CSV: {macro_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading Macros CSV: {macro_file}") from e

        if not less_strict:
            return self.get_macro(curr_db, macro_name, True)
        else:
            return (
                f"Macro '{macro_name}' not found. Make sure you're using the correct tool "
                "with correct args."
            )

    def get_global_var(
        self,
        curr_db: str,
        global_var_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return a global variable from GlobalVars.csv matching global_var_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            global_var_name (str): The name of the global variable to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with ['global_var_name','file','start_line','end_line'] if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If GlobalVars CSV file cannot be read (not found, permission denied, etc.).
        """
        global_var_file = os.path.join(curr_db, "GlobalVars.csv")
        keys = ["global_var_name", "file", "start_line", "end_line"]
        var_name_only = global_var_name.split("::")[-1]

        try:
            with open(global_var_file, "r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if var_name_only in line:
                        data = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
                        data_dict = dict(zip(keys, data))
                        if not data_dict:
                            continue

                        actual_name = data_dict["global_var_name"].replace("\"", "")
                        if (actual_name == var_name_only
                                or (less_strict and var_name_only in actual_name)):
                            return data_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"GlobalVars CSV file not found: {global_var_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading GlobalVars CSV: {global_var_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading GlobalVars CSV: {global_var_file}") from e

        if not less_strict:
            return self.get_global_var(curr_db, global_var_name, True)
        else:
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a macro or should you use another tool?"
            )

    def get_class(
        self,
        curr_db: str,
        class_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return class info (type, class_name, file, start_line, end_line, simple_name)
        from Classes.csv for class_name. If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            class_name (str): The name of the class/struct/union to find.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with keys ['type','class_name','file','start_line','end_line','simple_name']
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Classes CSV file cannot be read (not found, permission denied, etc.).
        """
        classes_file = os.path.join(curr_db, "Classes.csv")
        keys = ["type", "class_name", "file", "start_line", "end_line", "simple_name"]
        class_name_only = class_name.split("::")[-1]

        try:
            with open(classes_file, "r", encoding="utf-8") as f:
                while True:
                    row = f.readline()
                    if not row:
                        break
                    if class_name_only in row:
                        row_split = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', row)
                        row_dict = dict(zip(keys, row_split))
                        if not row_dict:
                            continue

                        actual_class = row_dict["class_name"].replace("\"", "")
                        simple_class = row_dict["simple_name"].replace("\"", "")
                        if (
                            actual_class == class_name_only
                            or simple_class == class_name_only
                            or (less_strict and class_name_only in actual_class)
                            or (less_strict and class_name_only in simple_class)
                        ):
                            return row_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Classes CSV file not found: {classes_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading Classes CSV: {classes_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading Classes CSV: {classes_file}") from e

        if not less_strict:
            return self.get_class(curr_db, class_name, True)
        else:
            return f"Class '{class_name}' not found. Could it be a Namespace?"

    def get_caller_function(
        self,
        function_tree_file: str,
        current_function: Dict[str, str]
    ) -> Union[str, Dict[str, str]]:
        """
        Return the caller function from function_tree_file that calls current_function.
        获取当前函数的“父函数”（即调用者）。
        利用 CodeQL 生成的调用图（Call Graph）信息，我们可以从当前函数向上回溯。
        这在分析污点传播路径时至关重要（例如：此处的脏数据是从哪个上层函数传进来的？）。

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            current_function (Dict[str, str]): The function dictionary whose caller we want.

        Returns:
            Union[str, Dict[str, str]]:
                - Dict describing the caller if found
                - or an error string if the caller wasn't found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        # 获取当前函数记录中存储的 caller_id (通常是 CodeQL 内部生成的唯一标识符)
        caller_id = current_function["caller_id"].replace("\"", "").strip()

        try:
            with open(function_tree_file, "r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    # 快速过滤：如果当前行不包含我们要找的 ID，直接跳过
                    if caller_id in line:
                        data = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
                        data_dict = dict(zip(keys, data))
                        if not data_dict:
                            continue
                        # 核心匹配逻辑：找到那一行，它的 function_id 等于我们要找的 caller_id
                        # 这意味着那一行描述的就是我们的父函数
                        if data_dict["function_id"].replace("\"", "").strip() == caller_id:
                            return data_dict
        except FileNotFoundError as e:
            raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e

        # Fallback if 'caller_id' is in format file:line
        # 兼容性处理：有时 caller_id 不是一个数字 ID，而是一个 "文件:行号" 的格式
        # 这种情况下，我们解析出行号，然后复用 get_function_by_line 来定位函数
        maybe_line = caller_id.split(":")
        if len(maybe_line) == 2:
            file_part, line_part = maybe_line
            function = self.get_function_by_line(function_tree_file, file_part[1:], int(line_part))
            if function:
                return function

        return (
            "Caller function was not found. "
            "Make sure you are using the correct tool with the correct args."
        )

    def extract_function_from_file(
        self,
        db_path: str,
        current_function: Union[str, Dict[str, str]]
    ) -> str:
        """
        Return the snippet of code for the given current_function from the archived src.zip.
        从 CodeQL 数据库自带的源码压缩包 (src.zip) 中提取指定函数的源代码。
        这避免了我们需要单独去下载或解压原始仓库的麻烦，因为 CodeQL DB 已经内置了一份完整的源码快照。

        Args:
            db_path (str): Path to the CodeQL database directory.
            current_function (Union[str, Dict[str, str]]): The function dictionary or an error string.

        Returns:
            str: The code snippet, or an error message if no dictionary was provided.
        
        Raises:
            CodeQLError: If ZIP file cannot be read or file not found in archive.
                This exception is raised by `read_file_lines_from_zip()` and propagated here.
        """
        if not isinstance(current_function, dict):
            return str(current_function)

        src_zip = os.path.join(db_path, "src.zip")
        # 路径修正：CSV 中的路径通常以 "/" 开头，但在 zip 包内是相对路径，所以去掉开头的 "/"
        file_path = current_function["file"].replace("\"", "")[1:]
        
        # 从 zip 包中读取整个文件的内容
        code_file = read_file_lines_from_zip(src_zip, file_path)
        lines = code_file.split("\n")

        start_line = int(current_function["start_line"])
        end_line = int(current_function["end_line"])
        
        # 切片提取：只保留属于该函数的行
        snippet_lines = lines[start_line - 1:end_line]

        # 格式化输出：给每一行加上行号，方便 AI 引用
        # 格式示例：
        # file: src/main.c
        # 105: int main() {
        # 106:     return 0;
        # 107: }
        snippet = "\n".join(
            f"{start_line - 1 + i}: {text}" for i, text in enumerate(snippet_lines)
        )
        return f"file: {file_path}\n{snippet}"

    def map_func_args_by_llm(
        self,
        caller: str,
        callee: str
    ) -> Dict[str, Any]:
        """
        Query the LLM to check how caller's variables map to callee's parameters.
        For example, used for analyzing function call relationships.
        专门调用 LLM 来进行“数据流映射分析”。
        当 AI 沿着调用链回溯时，它不仅需要知道“函数 A 调用了函数 B”，
        更需要知道“A 中的变量 x 是对应 B 中的参数 arg1 还是 arg2”。
        这个函数就是让 LLM 来帮我们理清这层参数传递关系。

        Args:
            caller (str): The code snippet of the caller function.
            callee (str): The code snippet of the callee function.

        Returns:
            Dict[str, Any]: The LLM response object from `self.client`.
        
        Raises:
            LLMApiError: If LLM API call fails (rate limits, timeouts, auth failures, etc.).
        """
        # 专门设计的 Prompt：要求 AI 仅提取变量映射关系
        # 格式示例：my_buffer (caller_name) -> dest_buf (callee_name)
        args_prompt = (
            "Given caller function and callee function.\n"
            "Write only what are the names of the vars in the caller that were sent to the callee "
            "and what are their names in the callee.\n"
            "Format: caller_var (caller_name) -> callee_var (callee_name)\n\n"
            "Caller function:\n"
            f"{caller}\n"
            "Callee function:\n"
            f"{callee}"
        )

        # Use the main model from config
        model_name = self.model if self.model else "gpt-4o"
        
        try:
            # 发起一次轻量级的 LLM 调用（通常不需要很强的推理能力，甚至可以用更便宜的模型）
            response = litellm.completion(
                model=model_name,
                messages=[{"role": "user", "content": args_prompt}]
            )
            return response.choices[0].message
        except litellm.RateLimitError as e:
            raise LLMApiError(f"Rate limit exceeded for LLM API: {e}") from e
        except litellm.Timeout as e:
            raise LLMApiError(f"LLM API request timed out: {e}") from e
        except litellm.AuthenticationError as e:
            raise LLMApiError(f"LLM API authentication failed: {e}") from e
        except litellm.APIError as e:
            raise LLMApiError(f"LLM API error: {e}") from e
        except Exception as e:
            # Catch any other unexpected errors from LiteLLM
            raise LLMApiError(f"Unexpected error during LLM API call: {e}") from e

    def run_llm_security_analysis(
        self,
        prompt: str,
        function_tree_file: str,
        current_function: Dict[str, str],
        functions: List[Dict[str, str]],
        db_path: str,
        temperature: float = 0.2,
        top_p: float = 0.2,
        trace: bool = False
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Main loop to keep querying the LLM with the MESSAGES context plus
        any new system instructions or tool calls, until a final answer with
        a recognized status code is reached or we exhaust a tool-call limit.
        这是 LLM 分析引擎的“主循环” (Main Loop)。
        它实现了一个完整的自主 Agent 流程：
        思考 -> 决定调用工具 -> 执行工具 -> 观察结果 -> 再思考 -> ... -> 得出结论。

        Args:
            prompt (str): The user prompt for the LLM to process.
            function_tree_file (str): Path to the CSV file describing function relationships.
            current_function (Dict[str, str]): The current function dict for context.
            functions (List[Dict[str, str]]): List of function dictionaries.
            db_path (str): Path to the CodeQL DB folder.
            temperature (float, optional): Sampling temperature. Defaults to 0.2.
            top_p (float, optional): Nucleus sampling. Defaults to 0.2.

        Returns:
            Tuple[List[Dict[str, Any]], str]:
                - The final conversation messages,
                - The final content from the LLM's last message.
        
        Raises:
            RuntimeError: If LLM model not initialized.
            LLMApiError: If LLM API call fails (rate limits, timeouts, auth failures, etc.).
            CodeQLError: If CodeQL database files cannot be read (from tool calls).
        """
        if not self.model:
            raise RuntimeError("LLM model not initialized. Call init_llm_client() first.")
        
        got_answer = False
        db_path_clean = db_path.replace(" ", "")
        all_functions = functions # 维护一个“已知函数”的上下文列表

        # 初始化对话历史：加载预设的 System Prompts，并加入用户的初始漏洞描述
        messages: List[Dict[str, Any]] = self.MESSAGES[:]
        messages.append({"role": "user", "content": prompt})

        amount_of_tools = 0
        final_content = ""
        iteration = 0
        printed_idx = 0

        # 进入自主思考循环，直到 AI 给出最终结论
        while not got_answer:
            iteration += 1
            print(f"[LLMAnalyzer] Iteration {iteration} start", flush=True)
            print(f"[LLMAnalyzer] Conversation send (new messages={len(messages) - printed_idx})", flush=True)
            for m in messages[printed_idx:]:
                role = m.get("role")
                name = m.get("name")
                tool_call_id = m.get("tool_call_id")
                print(f"[LLMAnalyzer] -> role={role} name={name if name else ''} tool_call_id={tool_call_id if tool_call_id else ''}", flush=True)
                tc = m.get("tool_calls")
                if tc:
                    try:
                        print(f"[LLMAnalyzer] -> tool_calls={json.dumps([{'name': x.function.name, 'arguments': x.function.arguments} for x in tc])}", flush=True)
                    except Exception:
                        print(f"[LLMAnalyzer] -> tool_calls={tc}", flush=True)
                content = m.get("content")
                if content is not None:
                    print(content, flush=True)
            printed_idx = len(messages)
            # Send the current messages + tools to the LLM endpoint
            try:
                # 调用 LLM，传入完整的对话历史和可用的工具列表
                response = litellm.completion(
                    model=self.model,
                    messages=messages,
                    tools=self.tools,
                    temperature=temperature,
                    top_p=top_p
                )
                print(f"[LLMAnalyzer] Iteration {iteration} response received", flush=True)
            except litellm.RateLimitError as e:
                print(f"[LLMAnalyzer] RateLimitError: {e}", flush=True)
                raise LLMApiError(f"Rate limit exceeded for LLM API: {e}") from e
            except litellm.Timeout as e:
                print(f"[LLMAnalyzer] Timeout: {e}", flush=True)
                raise LLMApiError(f"LLM API request timed out: {e}") from e
            except litellm.AuthenticationError as e:
                print(f"[LLMAnalyzer] AuthenticationError: {e}", flush=True)
                raise LLMApiError(f"LLM API authentication failed: {e}") from e
            except litellm.APIError as e:
                print(f"[LLMAnalyzer] APIError: {e}", flush=True)
                raise LLMApiError(f"LLM API error: {e}") from e
            except Exception as e:
                # Catch any other unexpected errors from LiteLLM
                print(f"[LLMAnalyzer] UnexpectedError: {e}", flush=True)
                raise LLMApiError(f"Unexpected error during LLM API call: {e}") from e

            content_obj = response.choices[0].message
            # 将 AI 的回复（可能是文本，也可能是工具调用请求）加入对话历史
            messages.append({
                "role": content_obj.role,
                "content": content_obj.content,
                "tool_calls": content_obj.tool_calls
            })
            print(f"[LLMAnalyzer] Conversation recv (new messages=1)", flush=True)
            print(f"[LLMAnalyzer] <- role={content_obj.role}", flush=True)
            if content_obj.tool_calls:
                try:
                    print(f"[LLMAnalyzer] <- tool_calls={json.dumps([{'name': x.function.name, 'arguments': x.function.arguments} for x in content_obj.tool_calls])}", flush=True)
                except Exception:
                    print(f"[LLMAnalyzer] <- tool_calls={content_obj.tool_calls}", flush=True)
            if content_obj.content is not None:
                print(content_obj.content, flush=True)
            printed_idx = len(messages)

            final_content = content_obj.content or ""
            tool_calls = content_obj.tool_calls
            preview = (final_content[:200] + "...") if len(final_content) > 200 else final_content
            has_tools = bool(tool_calls)
            print(f"[LLMAnalyzer] Iteration {iteration} content_len={len(final_content)} has_tools={has_tools}", flush=True)
            if preview:
                print(f"[LLMAnalyzer] Iteration {iteration} preview: {preview}", flush=True)

            # 分支 1：AI 没有调用工具，而是直接回复了文本
            if not tool_calls:
                # Check if we have a recognized status code
                # 检查回复中是否包含我们约定的状态码（如 1337, 1007）
                if final_content and any(code in final_content for code in ["1337", "1007", "7331", "3713"]):
                    print(f"[LLMAnalyzer] Iteration {iteration} status detected, finishing", flush=True)
                    got_answer = True # 循环结束，任务完成
                else:
                    # 如果 AI 说了一堆废话但没给结论，系统强制提醒它遵守规范
                    messages.append({
                        "role": "system",
                        "content": "Please follow all the instructions!"
                    })
                    print(f"[LLMAnalyzer] Iteration {iteration} no status, added follow-up reminder", flush=True)
            # 分支 2：AI 请求调用工具
            else:
                amount_of_tools += 1
                arg_messages: List[Dict[str, Any]] = []
                print(f"[LLMAnalyzer] Iteration {iteration} tool_calls={len(tool_calls)} total_tools_used={amount_of_tools}", flush=True)

                # 处理每一个工具调用请求（有时 AI 会一次性请求多个工具并行执行）
                for tc in tool_calls:
                    tool_call_id = tc.id
                    tool_function_name = tc.function.name
                    tool_args = tc.function.arguments
                    print(f"[LLMAnalyzer] Tool request: {tool_function_name}", flush=True)

                    # Convert tool_args to a dict if it's a JSON string
                    if not isinstance(tool_args, dict):
                        tool_args = json.loads(tool_args)
                    else:
                        # Ensure consistent string for role=tool message
                        tc.function.arguments = json.dumps(tool_args)
                    print(f"[LLMAnalyzer] Tool args: {tool_args}", flush=True)

                    response_msg = ""

                    # Evaluate which tool to call
                    # 根据函数名分发到对应的 Python 方法
                    if tool_function_name == 'get_function_code' and "function_name" in tool_args:
                        child_function, parent_function = self.get_function_by_name(
                            function_tree_file, tool_args["function_name"], all_functions
                        )
                        if isinstance(child_function, dict):
                            all_functions.append(child_function)
                        child_code = self.extract_function_from_file(db_path_clean, child_function)
                        response_msg = child_code
                        print(f"[LLMAnalyzer] get_function_code returned child", flush=True)

                        # 增强逻辑：如果找到了函数，顺便自动分析一下调用参数映射关系
                        if isinstance(child_function, dict) and isinstance(parent_function, dict):
                            caller_code = self.extract_function_from_file(db_path_clean, parent_function)
                            args_content = self.map_func_args_by_llm(caller_code, child_code)
                            arg_messages.append({
                                "role": args_content.role,
                                "content": args_content.content
                            })
                            print(f"[LLMAnalyzer] args mapping added", flush=True)

                    elif tool_function_name == 'get_caller_function':
                        caller_function = self.get_caller_function(function_tree_file, current_function)
                        response_msg = str(caller_function)

                        if isinstance(caller_function, dict):
                            all_functions.append(caller_function)
                            caller_code = self.extract_function_from_file(db_path_clean, caller_function)
                            # 拼接提示词，明确告诉 AI 这是谁的调用者
                            response_msg = (
                                f"Here is the caller function for '{current_function['function_name']}':\n"
                                + caller_code
                            )
                            # 同样自动进行参数映射分析
                            args_content = self.map_func_args_by_llm(
                                caller_code,
                                self.extract_function_from_file(db_path_clean, current_function)
                            )
                            arg_messages.append({
                                "role": args_content.role,
                                "content": args_content.content
                            })
                            # 更新当前上下文焦点到调用者
                            current_function = caller_function
                            print(f"[LLMAnalyzer] get_caller_function updated current", flush=True)

                    elif tool_function_name == 'get_macro' and "macro_name" in tool_args:
                        macro = self.get_macro(db_path_clean, tool_args["macro_name"])
                        if isinstance(macro, dict):
                            response_msg = macro["body"]
                        else:
                            response_msg = macro
                        print(f"[LLMAnalyzer] get_macro processed", flush=True)

                    elif tool_function_name == 'get_global_var' and "global_var_name" in tool_args:
                        global_var = self.get_global_var(db_path_clean, tool_args["global_var_name"])
                        if isinstance(global_var, dict):
                            global_var_code = self.extract_function_from_file(db_path_clean, global_var)
                            response_msg = global_var_code
                        else:
                            response_msg = global_var
                        print(f"[LLMAnalyzer] get_global_var processed", flush=True)

                    elif tool_function_name == 'get_class' and "object_name" in tool_args:
                        curr_class = self.get_class(db_path_clean, tool_args["object_name"])
                        if isinstance(curr_class, dict):
                            class_code = self.extract_function_from_file(db_path_clean, curr_class)
                            response_msg = class_code
                        else:
                            response_msg = curr_class
                        print(f"[LLMAnalyzer] get_class processed", flush=True)

                    else:
                        response_msg = (
                            f"No matching tool '{tool_function_name}' or invalid args {tool_args}. "
                            "Try again."
                        )
                        print(f"[LLMAnalyzer] unknown tool or args", flush=True)

                    # 将工具执行结果封装为 role='tool' 的消息，加入对话历史
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call_id,
                        "name": tool_function_name,
                        "content": response_msg
                    })

                # 将参数映射分析的结果也加入对话历史
                messages += arg_messages
                if arg_messages:
                    print(f"[LLMAnalyzer] Conversation add args mapping (new messages={len(arg_messages)})", flush=True)
                    for m in arg_messages:
                        print(f"[LLMAnalyzer] -> role={m.get('role')}", flush=True)
                        if m.get("content") is not None:
                            print(m.get("content"), flush=True)
                    printed_idx = len(messages)

                # 安全熔断机制：防止 AI陷入无限循环调用工具
                # 如果调用次数超过 6 次还没有结论，强制让它停止并给出“数据不足”的结论
                if amount_of_tools >= 6:
                    messages.append({
                        "role": "system",
                        "content": (
                            "You called too many tools! If you still can't give a clear answer, "
                            "return the 'more data' status."
                        )
                    })
                    print(f"[LLMAnalyzer] fuse triggered after {amount_of_tools} tool calls", flush=True)

        return messages, final_content

def main() -> None:
    parser = argparse.ArgumentParser(prog="llm_analyzer", description="Run LLMAnalyzer standalone")
    parser.add_argument("--db", required=True, help="Path to CodeQL database directory")
    parser.add_argument("--function-tree", help="Path to FunctionTree.csv; defaults to <db>/FunctionTree.csv")
    parser.add_argument("--file", required=True, help="File path as present in FunctionTree.csv")
    parser.add_argument("--line", type=int, required=True, help="Line number inside the target function")
    parser.add_argument("--prompt", default="Analyze the security impact of the issue.", help="Prompt to send to the LLM")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top_p", type=float, default=0.2)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()

    analyzer = LLMAnalyzer()
    try:
        print("[LLMAnalyzer] init client", flush=True)
        analyzer.init_llm_client()
    except LLMConfigError as e:
        print(f"LLMConfigError: {e}")
        sys.exit(1)

    function_tree_file = args.function_tree if args.function_tree else os.path.join(args.db, "FunctionTree.csv")
    print(f"[LLMAnalyzer] locate function from {function_tree_file}", flush=True)
    try:
        current_function = analyzer.get_function_by_line(function_tree_file, args.file, args.line)
    except CodeQLError as e:
        print(f"FunctionLocateError: {e}")
        sys.exit(2)
    if current_function is None:
        print("FunctionNotFound: could not locate function by file and line")
        sys.exit(2)
    print(f"[LLMAnalyzer] function located: {current_function.get('function_name','<unknown>')}", flush=True)

    functions = [current_function]
    try:
        print("[LLMAnalyzer] run analysis", flush=True)
        messages, content = analyzer.run_llm_security_analysis(
            prompt=args.prompt,
            function_tree_file=function_tree_file,
            current_function=current_function,
            functions=functions,
            db_path=args.db,
            temperature=args.temperature,
            top_p=args.top_p,
            trace=args.trace,
        )
    except (LLMApiError, CodeQLError) as e:
        print(f"RunError: {e}")
        sys.exit(3)

    print(content if content else "")

if __name__ == "__main__":
    main()


