#!/usr/bin/env python3

import click
import yaml
import os
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

\033[35m[>] scan\033[0m
    Run security scans without implementing fixes
    Usage: agentic-security scan [--config CONFIG]

\033[35m[>] analyze\033[0m
    Analyze security issues and optionally implement fixes
    Usage: agentic-security analyze [--config CONFIG] [--auto-fix]

\033[35m[>] run\033[0m
    Run the complete security pipeline
    Usage: agentic-security run [--config CONFIG]

\033[35m[>] validate\033[0m
    Validate configuration file
    Usage: agentic-security validate [--config CONFIG]

\033[35m[>] version\033[0m
    Show version information
    Usage: agentic-security version

\033[36m╔══════════════════════════════════════════════════════════════╗
║                         Options                             ║
╚══════════════════════════════════════════════════════════════╝\033[0m

\033[35m--config, -c\033[0m
    Path to configuration file (default: config.yml)

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
    required_vars = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'SLACK_WEBHOOK']
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
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
def scan(config: str):
    """Run security scans without implementing fixes"""
    print(CYBER_BANNER)
    if not validate_environment():
        return
    
    print_cyber_status("Initializing security scan...", "info")
    pipeline = SecurityPipeline(config)
    results = pipeline.run_security_checks()
    
    # Display results
    for check_type, check_results in results.items():
        print_cyber_status(f"\n{check_type.upper()} Scan Results:", "info")
        for result in check_results:
            max_severity = pipeline._get_max_severity(result)
            print_cyber_status(f"Maximum severity: {max_severity}", 
                           "error" if max_severity >= pipeline.critical_threshold else "info")
            if max_severity >= pipeline.critical_threshold:
                print_cyber_status("Critical vulnerabilities found!", "error")

@cli.command()
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
@click.option('--auto-fix/--no-auto-fix', default=False, help='Automatically implement fixes')
def analyze(config: str, auto_fix: bool):
    """Analyze security issues and optionally implement fixes"""
    print(CYBER_BANNER)
    if not validate_environment():
        return
    
    print_cyber_status("Initializing security analysis...", "info")
    pipeline = SecurityPipeline(config)
    
    # Run architecture review
    review_results = pipeline.run_architecture_review()
    print_cyber_status("\nArchitecture Review Results:", "info")
    print(f"\033[36m{review_results['output']}\033[0m")
    
    if auto_fix and review_results.get('suggestions'):
        print_cyber_status("\nImplementing suggested fixes...", "info")
        if pipeline.implement_fixes(review_results['suggestions']):
            print_cyber_status("Fixes implemented successfully", "success")
        else:
            print_cyber_status("Some fixes could not be implemented", "warning")

@cli.command()
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
def run(config: str):
    """Run the complete security pipeline"""
    print(CYBER_BANNER)
    if not validate_environment():
        return
    
    print_cyber_status("Initializing security pipeline...", "info")
    pipeline = SecurityPipeline(config)
    
    if pipeline.run_pipeline():
        print_cyber_status("Pipeline completed successfully", "success")
    else:
        print_cyber_status("Pipeline failed", "error")
        exit(1)

@cli.command()
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
def validate(config: str):
    """Validate configuration file"""
    print(CYBER_BANNER)
    print_cyber_status(f"Validating configuration file: {config}", "info")
    config_data = load_config(config)
    
    if not config_data:
        print_cyber_status("Invalid configuration", "error")
        exit(1)
    
    # Validate required sections
    required_sections = ['security', 'notifications', 'aider']
    missing_sections = [section for section in required_sections if section not in config_data]
    
    if missing_sections:
        print_cyber_status("Missing required configuration sections:", "error")
        for section in missing_sections:
            print_cyber_status(f"  - {section}", "error")
        exit(1)
    
    print_cyber_status("Configuration is valid", "success")

@cli.command()
def version():
    """Show version information"""
    print(CYBER_BANNER)
    print_cyber_status("Agentic Security CLI v1.0.0", "info")

if __name__ == '__main__':
    cli()
