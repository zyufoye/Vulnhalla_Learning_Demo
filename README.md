# Vulnhalla_Learning_Demo


## Vulnhalla 

Vulnhalla 可以自动化执行完整的安全分析流程：

1. 从 GitHub 获取指定编程语言的代码库
2. 下载其对应的 CodeQL 数据库（如果可用）
3. 在数据库上运行 CodeQL 查询以检测安全或代码质量问题
4. 使用 LLM（ChatGPT、Gemini 等）对结果进行后续处理，以分类和过滤问题

项目提供了直接从 Github fetch repositories 的能力，但是需要本地配置 GitHub API token，为了简化实验流程，就直接把要分析的 Program git clone 到本地，然后本地生成 CodeQL Database 再进行后续的结果处理，**这个 Project 的重点就是在于结果处理**。

## 🚀 QuickStart

环境要求：

- python 3.11
- CodeQL CLI
- LLM API Key

虚拟环境配置：

```bash
conda create -n vulnhalla python=3.11

conda activate vulnhalla

pip install -r requirements.txt
```

miniconda 下载可参考这篇文章： 。

配置文件修改 project 中以 OpenAI gpt-4o为例：

```conf
CODEQL_PATH=codeql
GITHUB_TOKEN=ghp_your_token_here
PROVIDER=openai
MODEL=gpt-4o
OPENAI_API_KEY=your-api-key-here
LLM_TEMPERATURE=0.2
LLM_TOP_P=0.2

# Optional: Logging Configuration
LOG_LEVEL=INFO                  # DEBUG, INFO, WARNING, ERROR
LOG_FILE=                       # Optional: path to log file (e.g., logs/vulnhalla.log)
LOG_FORMAT=default              # default or json
# LOG_VERBOSE_CONSOLE=false     # If true, WARNING/ERROR use full format (timestamp - logger - level - message)
```

参数解析：

- CODEQL_PATH：指定 CodeQL 可执行文件的路径或命令名，用于运行代码安全分析（如漏洞扫描）。如果已加入系统 PATH，直接写 codeql 即可；
- GITHUB_TOKEN：GitHub 访问令牌，用于访问私有仓库、拉取代码、调用 GitHub API（如获取 PR、Issue、仓库信息等）；
- PROVIDER/MODEL/OPENAI_API_KEY：大模型相关配置，可替换为对应厂商；
- LLM_TEMPERATURE：控制模型输出的随机性，值越低输出越稳定、保守，适合分析、审计、代码检查等场景；
- LLM_TOP_P：控制采样范围（nucleus sampling），限制模型在高概率词汇中选择，进一步提升结果一致性和可控性；
- LOG_LEVEL=INFO：日志级别，控制输出信息的详细程度，DEBUG是最详细的；
- LOG_FILE：日志文件输出路径，留空表示仅输出到控制台；
- LOG_FORMAT/LOG_VERBOSE_CONSOLE：日志格式和日志记录格式；

```bash
cp .env.example .env

python setup.py

# 初始化CodeQL套件
cd data/queries/cpp/tools
codeql pack install
cd ../issues
codeql pack install
cd ../../../..
```

使用单个命令运行完整的 pipeline：

```bash
# Analyze a specific repository
python src/pipeline.py redis/redis

# Analyze top 100 repositories
python src/pipeline.py
```

这个 pipeline 会自动执行：获取CodeQL数据库，在所有下载的数据库上运行 CodeQL 查询，使用 LLM 分析结果并保存到 output/results/，打开 UI 浏览结果。

Project 还提供了一个示例脚本，运行一个端到端示例：

```bash
python examples/example.py
```

这个 example 会获取 videolan/vlc 和 redis/redis 的 CodeQL 数据库，在所有下载的数据库上运行 CodeQL 查询，使用 LLM 分析结果并保存到 output/results/。

Vulnhalla 包含一个功能齐全的用户界面，用于浏览和探索分析结果。

```bash
python src/ui/ui_app.py
# or
python examples/ui_example.py
```
