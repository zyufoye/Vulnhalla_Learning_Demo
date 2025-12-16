#!/usr/bin/env python3
"""
Pipeline orchestration for Vulnhalla.
This module coordinates the complete analysis pipeline:
1. Fetch CodeQL databases
2. Run CodeQL queries
3. Classify results with LLM
4. Open UI (optional)
"""
import sys
from pathlib import Path
from typing import Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries
from src.utils.config import get_codeql_path
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import setup_logging, get_logger
from src.vulnhalla import IssueAnalyzer
from src.ui.ui_app import main as ui_main

# Initialize logging
setup_logging()
logger = get_logger(__name__)


def analyze_pipeline(repo: Optional[str] = None,
                      lang: str = "c", 
                      threads: int = 16, 
                      open_ui: bool = True,
                      db_path: Optional[str] = None,   # ✅ 新增：本地 CodeQL DB 路径
                      ) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch, analyze, classify, and optionally open UI.
    Args:
        repo: Optional GitHub repository name (e.g., "redis/redis"). If None, fetches top repos.
        lang: Programming language code. Defaults to "c".
        threads: Number of threads for CodeQL operations. Defaults to 16.
        open_ui: Whether to open the UI after completion. Defaults to True.
    """
    logger.info("🚀 Starting Vulnhalla Analysis Pipeline")
    logger.info("=" * 60)
    
    # Validate configuration before starting
    validate_and_exit_on_error()
    
    # Step 1: Fetch CodeQL databases
    logger.info("\n[1/4] Fetching CodeQL Databases")
    logger.info("-" * 60)
    if db_path:
        logger.info("Using local CodeQL database: %s", db_path)
        if not Path(db_path).exists():
            logger.error("❌ Local database path does not exist: %s", db_path)
            sys.exit(1)
    
    else:
        if repo:
            logger.info("Fetching database for: %s", repo)
            fetch_codeql_dbs(lang=lang, threads=threads, single_repo=repo)
        else:
            logger.info("Fetching top repositories for language: %s", lang)
            fetch_codeql_dbs(lang=lang, max_repos=100, threads=4)
    # Step 2: Run CodeQL queries
    logger.info("\n[2/4] Running CodeQL Queries")
    logger.info("-" * 60)
    compile_and_run_codeql_queries(
        codeql_bin=get_codeql_path(),
        lang=lang,
        threads=threads,
        timeout=300,
        db_path=db_path,   # ✅ 新增：把本地 DB 传下去
    )
    # Step 3: Classify results with LLM
    logger.info("\n[3/4] Classifying Results with LLM")
    logger.info("-" * 60)
    analyzer = IssueAnalyzer(lang=lang)
    analyzer.run()
    # Step 4: Open UI (if requested)
    if open_ui:
        logger.info("\n[4/4] Opening UI")
        logger.info("-" * 60)
        logger.info("✅ Pipeline completed successfully!")
        logger.info("Opening results UI...")
        ui_main()
    else:
        logger.info("\n✅ Pipeline completed successfully!")
        logger.info("View results with: python src/ui/ui_app.py")


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    Usage:
        vulnhalla-analyze                    # Analyze top 100 repos
        vulnhalla-analyze redis/redis        # Analyze specific repo
    """
    # Parse command line arguments
    repo = None
    if len(sys.argv) > 1:
        if sys.argv[1] == "--db" and len(sys.argv) > 2:
            db_path = sys.argv[2]
        else:
            repo = sys.argv[1]
            if "/" not in repo:
                logger.error("❌ Error: Repository must be in format 'org/repo'")
                logger.error("   Example: python src/pipeline.py redis/redis")
                logger.error("   Or run without arguments to analyze top repositories")
                sys.exit(1)
    analyze_pipeline(repo=repo, db_path=db_path)

if __name__ == '__main__':
    main_analyze()