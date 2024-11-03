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

\033[35m[>] scan\033[0m
    Run security scans without implementing fixes
    Usage: agentic-security scan [--config CONFIG] [--path PATH]...

\033[35m[>] analyze\033[0m
    Analyze security issues and optionally implement fixes
    Usage: agentic-security analyze [--config CONFIG] [--auto-fix]

\033[35m[>] run\033[0m
    Run the complete security pipeline
    Usage: agentic-security run [--config CONFIG]

\033[35m[>] review\033[0m
    Generate security review report
    Usage: agentic-security review [--path PATH]... [--output OUTPUT]

\033[35m[>] validate\033[0m
    Validate configuration file
    Usage: agentic-security validate [--config CONFIG]

\033[35m[>] test\033[0m
    Run security pipeline tests
    Usage: agentic-security test [--verbose]

\033[35m[>] version\033[0m
    Show version information
    Usage: agentic-security version

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
@click.option('--path', '-p', multiple=True, help='Paths to scan (files or directories)')
@click.option('--auto-fix/--no-auto-fix', default=False, help='Automatically apply fixes without prompting')
@click.option('--timeout', '-t', default=600, help='Scan timeout in seconds', type=int)
@click.option('--exclude', '-e', multiple=True, help='Patterns to exclude from scan')
@click.option('--output', '-o', type=click.Path(), help='Output report path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--no-progress', is_flag=True, help='Disable progress animation')
def scan(path, auto_fix, timeout, exclude, output, verbose, no_progress):
    """Run security scans on specified paths"""
    print(CYBER_BANNER)
    if not validate_environment():
        sys.exit(1)

    # Set environment variable for verbose mode
    if verbose:
        os.environ['SECURITY_DEBUG'] = 'true'
        print("\n[36m[>] Starting security scan in verbose mode[0m")
        print(f"[36m[>] Scan time: {time.strftime('%Y-%m-%d %H:%M:%S')}[0m")
        print(f"[36m[>] Timeout: {timeout} seconds[0m")
        print(f"[36m[>] Paths: {', '.join(path) or '.'}[0m")
        if exclude:
            print(f"[36m[>] Excluding: {', '.join(exclude)}[0m")
        print("\n[36m[>] Scanning files...[0m")

    # Only show initialization sequence if progress is enabled
    if not no_progress:
        init_messages = [
            ("INITIALIZING NEURAL SCAN SEQUENCE", 0.3),
            ("LOADING SECURITY PROTOCOLS", 0.2),
            ("CALIBRATING QUANTUM SCANNERS", 0.2),
            ("ENGAGING CYBER-DEFENSE MATRIX", 0.3),
        ]
            
        for msg, delay in init_messages:
            sys.stdout.write(f"\r\033[35m[SYSTEM] \033[36m{msg}...\033[0m")
            sys.stdout.flush()
            time.sleep(delay)
            sys.stdout.write("\033[K")  # Clear line
        print("\n")
        
    if not path:
        print("[33m[!] No paths specified, please provide at least one path to scan[0m")
        return
            
    try:
        pipeline = SecurityPipeline('config.yml')
        results = pipeline.scan_paths(path or ['.'], auto_fix=auto_fix)
        
        if auto_fix and results.get('fixes_applied'):
            print("\n[32m[✓] Fixes applied successfully![0m")
            if results['fixes_applied'].get('branch'):
                print(f"\n[32m[✓] Created branch: {results['fixes_applied']['branch']}[0m")
        elif auto_fix:
            print("\n[31m[!] Some or all fixes could not be applied[0m")
            
        try:
            results = pipeline.scan_paths(
                paths=list(path),
                exclude=exclude,
                timeout=timeout,
                auto_fix=auto_fix,
                verbose=verbose
            )
        except KeyboardInterrupt:
            print("\n[33m[!] Scan interrupted by user. Partial results may be available.[0m")
            return
        except TimeoutError:
            print("\n[31m[!] Scan timed out. Please try scanning specific paths or increase timeout.[0m")
            return
            
        vulns = results.get('vulnerabilities', [])
        
        if output:
            pipeline.generate_report(results, output, verbose)
            print_cyber_status(f"Report generated at {output}", "success")

        if vulns:
            print("\nVulnerabilities Found:")
            print("=====================")
            
            for vuln in vulns:
                severity = vuln.get('severity', 'unknown').upper()
                score = vuln.get('score', 0.0)
                
                # Color code by severity
                color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[93m',      # Yellow
                    'MEDIUM': '\033[94m',    # Blue
                    'LOW': '\033[92m'        # Green
                }.get(severity, '')
                
                print(f"\n{color}[{severity}] {vuln['type']}\033[0m")
                print(f"File: {vuln['file']}")
                print(f"Score: {score}")
                if vuln.get('description'):
                    print(f"Details: {vuln['description']}")
            
            if auto_fix:
                print_cyber_status("Automatically applying fixes...", "info")
                if pipeline.implement_fixes([v['details'] for v in results['vulnerabilities']]):
                    print_cyber_status("Fixes applied successfully", "success")
                else:
                    print_cyber_status("Some fixes could not be applied", "warning")
            else:
                print_cyber_status("Run with --auto-fix to attempt automatic fixes", "info")
        else:
            print("\n[32m[✓] No vulnerabilities found. Your project is secure![0m")
            
    except Exception as e:
        print_cyber_status(f"Error: {str(e)}", "error")
        sys.exit(1)

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
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
@click.option('--verbose/--no-verbose', '-v/', default=False, help='Verbose output')
def test(config, verbose):
    """Run security pipeline tests"""
    print_cyber_status("Running security pipeline tests...", "info")
    
    try:
        import pytest
        args = ['tests/test_security_pipeline.py']
        if verbose:
            args.append('-v')
        
        exit_code = pytest.main(args)
        if exit_code == 0:
            print_cyber_status("All tests passed!", "success")
        else:
            print_cyber_status("Some tests failed", "error")
            sys.exit(1)
    except Exception as e:
        print_cyber_status(f"Error running tests: {str(e)}", "error")
        sys.exit(1)

@cli.command()
@click.option('--path', '-p', multiple=True, help='Paths to review')
@click.option('--output', '-o', type=click.Path(), help='Output markdown report path')
@click.option('--verbose/--no-verbose', '-v/', default=False, help='Verbose output')
@click.option('--config', '-c', default='config.yml', help='Path to configuration file')
def review(path: tuple, output: str, verbose: bool, config: str):
    """Generate security review report"""
    print_cyber_status("Security Review Report", "info")
    print_cyber_status("Starting analysis...", "info")
    
    if not path:
        path = ['.']
        
    try:
        from .security_pipeline import SecurityPipeline
        pipeline = SecurityPipeline(config)
        
        results = pipeline.review_paths(path, verbose)
        
        if output:
            pipeline.generate_review_report(results, output)
            print_cyber_status(f"Review report generated at {output}", "success")
        else:
            # Print review results to console
            pipeline.print_review_results(results, verbose)
            
    except Exception as e:
        print_cyber_status(f"Error: {str(e)}", "error")
        sys.exit(1)


def version():
    """Show version information"""
    print(CYBER_BANNER)
    print_cyber_status("Agentic Security CLI v1.0.0", "info")

if __name__ == '__main__':
    cli()
