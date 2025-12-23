
## 0.项目目标

- 学习Vulnhalla项目的架构设计，跑通该项目，然后根据核心思想设计修改成适配Java项目的架构
- 对每个模块进行分析，确定是否需要修改，是否需要新增模块，是否需要删除模块

## 1.运行方式

```bash
# pipeline分析
python src/pipeline.py redis/redis

# 结果展示
python src/ui/ui_app.py
```

## 2.核心流程（主线）

1. 从github fetch codeql database
2. 执行codeql查询
3. 用LLM对结果分类
4. UI展示分类结果

```txt
main_analyze()

analyze_pipeline(repo=repo) # repo是指定仓库进行分析

analyze_pipeline(repo: Optional[str] = None, lang: str = "c", threads: int = 16, open_ui: bool = True) -> None

    Step 1：fetch_codeql_dbs(lang=lang, threads=threads, single_repo=repo)

    Step 2：compile_and_run_codeql_queries(
            codeql_bin=get_codeql_path(),
            lang=lang,
            threads=threads,
            timeout=300
        )

    Step 3：analyzer = IssueAnalyzer(lang=lang)
        analyzer.run()
    
    Step 4：ui_main()
```

## 3 输入 && 输出

### Step 1：输入组织名和仓库名，项目会从 github 中自动拉取对应项目。

**输入** src/pipeline.py redis/redis

根据 redis/redis 去下载对应的codeql database，把文件下载到 output/zip_dbs/<语言>/<仓库名>.zip 目录中 

output/databases/ 存放解压后的 CodeQL 数据库

**输出** 从 GitHub 中下载的 codeql 数据库 zip 和解压后的内容 在 output/databases/ 目录下。

### Step 2： 执行 CodeQL 查询

**输入** 执行查询时，只需要输出 codeql 的执行路径，工具会根据预置的文件路径去找到数据库和查询文件

漏洞查询脚本目录：data/queries/cpp/issues
工具类查询脚本目录：data/queries/cpp/tools
待扫描数据库路径：output/databases

预编译所有查询和工具 compile_all_queries 输出qlx文件
获取所有的有效数据库 get_all_dbs 
run_queries_on_db 
    run_one_query 该过程会输出两个文件：FunctionTree.csv 和  issues.csv（bqrs转码为csv）

**输出** FunctionTree.csv 和 issues.csv 包含了函数信息和漏洞信息

### Step 3：LLM_analyzer 




## 4.模块（目前调通）

### 核心功能一 拉取 codeql databases

fetch_codeql_dbs 拉取codeql数据库 需指定参数 redis/redis
    download_db_by_name 指定仓库名进行数据库下载 
        filter_repos_by_db_and_lang 寻找对应语言的数据库
        download_and_extract_db 找到后下载并解压
Downloading repo redis/redis 下载了 redis.zip

拉取后解压的数据库结构如下 level=2
```bash

tree -L 2 ./

./
├── baseline-info.json
├── codeql-database.yml
├── db-cpp
│   ├── default
│   ├── semmlecode.cpp.dbscheme
│   └── semmlecode.cpp.dbscheme.stats
└── src.zip

```

### 核心功能二 执行CodeQL查询 compile_and_run_codeql_queries

compile_and_run_codeql_queries 编译并运行CodeQL查询
    compile_all_queries 预编译所有的查询内容
    get_all_dbs 获取所有数据库的路径
    run_queries_on_db 遍历所有数据库，对每个数据库都执行tools查询和issues漏洞查询
        run_one_query 执行单条查询

### 核心功能三 

src\llm\llm_analyzer.py

AI 安全专家 (Agent)，定义了一个 LLMAnalyzer 类，其实例化后就是一个拥有特定人设（“安全研究员”）的 AI 智能体。它的核心循环 ( run_llm_security_analysis ) 负责接收漏洞线索，然后不断地查代码、思考、再查代码，直到确认漏洞是否真实存在

**核心能力：** 本项目的核心就是赋予了智能体“阅读源码”的能力，通过定义 tools 列表给 agent添加代码查看工具






### LLM智能分析模块





## 5.模块（未调通）