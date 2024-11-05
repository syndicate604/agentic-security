#!/usr/bin/env python3

from datetime import datetime
from pathlib import Path
import click
import yaml
import os
import sys
import time
from dotenv import load_dotenv
from .security_pipeline import SecurityPipeline
from typing import Optional

CYBER_BANNER = """
\033[36m
    █████╗  ██████╗ ███████╗███╗   ██╗████████╗██╗ ██████╗
   ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝
   ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║██║     
   ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     
   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ██║╚██████╗
   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝
   \033[35m███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
\033[0m
\033[36m[ AI-Powered Security Scanner & Auto-Fix Pipeline ]\033[0m
\033[35m[ Created by rUv, cause he could. ]\033[0m

"""

CYBER_HELP = """
\033[36m╔══════════════════════════════════════════════════════════════╗
║                     Available Commands                      ║
╚══════════════════════════════════════════════════════════════╝\033[0m

\033[35m[>] analyze\033[0m
    Analyze security issues and optionally implement fixes
    Usage: agentic-security analyze [--config CONFIG] [--auto-fix]

\033[36m╔══════════════════════════════════════════════════════════════╗
║                         Options                             ║
╚══════════════════════════════════════════════════════════════╝\033[0m

\033[35m--config, -c\033[0m
    Path to configuration file (default: config.yml)

\033[35m--path, -p\033[0m
    Paths to scan or review (can be specified multiple times)

\033[35m--output, -o\033[0m
    Output markdown report path

\033[35m--verbose, -v\033[0m
    Enable verbose output

\033[35m--auto-fix\033[0m
    Automatically apply fixes without prompting

\033[35m--help\033[0m
    Show this cyberpunk-styled help message

\033[36m╔══════════════════════════════════════════════════════════════╗
║                         Options                             ║
╚══════════════════════════════════════════════════════════════╝\033[0m

\033[35m--config, -c\033[0m
    Path to configuration file (default: config.yml)

\033[35m--path, -p\033[0m
    Paths to scan or review (can be specified multiple times)

\033[35m--output, -o\033[0m
    Output markdown report path

\033[35m--verbose, -v\033[0m
    Enable verbose output

\033[35m--auto-fix\033[0m
    Automatically apply fixes without prompting

\033[35m--help\033[0m
    Show this cyberpunk-styled help message
"""

def print_cyber_status(message: str, status: str = "info") -> None:
    """Print cyberpunk-styled status messages"""
    colors = {
        "info": "\033[36m",    # Cyan
        "success": "\033[32m",  # Green
        "warning": "\033[33m",  # Yellow
        "error": "\033[31m",    # Red
    }
    color = colors.get(status, colors["info"])
    print(f"{color}[>] {message}\033[0m")

def load_config(config_file: str) -> dict:
    """Load configuration from file"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print_cyber_status(f"Config file not found: {config_file}", "error")
        return {}
    except yaml.YAMLError as e:
        print_cyber_status(f"Error parsing config file: {str(e)}", "error")
        return {}

def validate_environment() -> bool:
    """Validate required environment variables"""
    # Load environment variables from .env file securely
    load_dotenv(override=True)
    
    required_vars = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print_cyber_status("Missing required environment variables:", "error")
        for var in missing_vars:
            print_cyber_status(f"  - {var}", "error")
        return False
    return True

class CyberpunkGroup(click.Group):
    def format_help(self, ctx, formatter):
        print(CYBER_BANNER)
        print(CYBER_HELP)

@click.group(cls=CyberpunkGroup)
def cli():
    """Agentic Security CLI - AI-powered security scanning and fixing pipeline"""
    pass


@cli.command()
@click.option('--path', '-p', multiple=True, help='Paths to analyze')
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
@click.option('--auto-fix/--no-auto-fix', default=False, help='Automatically implement fixes')
@click.option('--verbose/--no-verbose', '-v/', default=False, help='Verbose output')
def analyze(path: tuple, config: str, auto_fix: bool, verbose: bool):
    """Analyze security issues and optionally implement fixes"""
    try:
        print(CYBER_BANNER)
        if not validate_environment():
            sys.exit(1)
        
        print_cyber_status("Initializing security analysis...", "info")
        pipeline = SecurityPipeline(config)
        
        if not path:
            path = ['.']  # Default to current directory if no path specified
            
        # Run security analysis on specified paths
        results = pipeline.scan_paths(path, auto_fix=auto_fix)
        
        # Generate unique report filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = Path('security_reports')
        report_dir.mkdir(exist_ok=True)
        report_file = report_dir / f'security_report_{timestamp}.md'
        
        # Generate the report
        pipeline.generate_review_report(results, str(report_file))
        print_cyber_status(f"\nSecurity report generated: {report_file}", "success")
        
        if verbose:
            print("\nAnalysis Results:")
            for vuln in results.get('vulnerabilities', []):
                print(f"\nFile: {vuln['file']}")
                print(f"Type: {vuln['type']}")
                print(f"Severity: {vuln['severity']}")
                if vuln.get('details', {}).get('description'):
                    print(f"Details: {vuln['details']['description']}")
        
        # Exit after completion
        sys.exit(0)
                
    except KeyboardInterrupt:
        print("\n\033[33m[!] Analysis interrupted. Saving partial results...\033[0m")
        # Still try to save the report if interrupted
        if 'results' in locals() and results:
            pipeline.generate_review_report(results, str(report_file))
            print_cyber_status(f"\nPartial report saved: {report_file}", "warning")
        sys.exit(1)
    except Exception as e:
        print_cyber_status(f"Error during analysis: {str(e)}", "error")
        sys.exit(1)


if __name__ == '__main__':
    cli()
