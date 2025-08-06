#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import argparse
import logging
import time
from pathlib import Path

from analyzers.code_analyzer import CodeAnalyzer
from utils.code_parser import CodeParser
from utils.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smart_code_review')

def load_config(config_path=None):
    """Load configuration from file or use defaults.
    
    Args:
        config_path (str, optional): Path to configuration file.
        
    Returns:
        dict: Configuration dictionary.
    """
    default_config = {
        "general": {
            "excluded_directories": ["node_modules", "__pycache__", "venv", ".git", ".idea"],
            "excluded_file_patterns": ["*.min.js", "*.map"]
        },
        "security": {
            "enabled_checks": {
                "sql_injection": True,
                "xss": True,
                "hardcoded_secrets": True,
                "insecure_functions": True,
                "os_command_injection": True
            },
            "severity_threshold": "medium"
        },
        "style": {
            "enabled": True
        },
        "static": {
            "unused_variables": True,
            "unreachable_code": True
        },
        "ml": {
            "enabled": True,
            "model_path": "data/models/pattern_model.pkl"
        }
    }
    
    if not config_path or not os.path.exists(config_path):
        logger.warning("No configuration file found. Using default built-in configuration.")
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
            
        # Merge user config with defaults
        for section in default_config:
            if section in user_config:
                if isinstance(default_config[section], dict) and isinstance(user_config[section], dict):
                    default_config[section].update(user_config[section])
                else:
                    default_config[section] = user_config[section]
        
        logger.info(f"Loaded configuration from {config_path}")
        return default_config
    except Exception as e:
        logger.error(f"Error loading configuration from {config_path}: {str(e)}")
        logger.warning("Using default built-in configuration.")
        return default_config

class SmartCodeReview:
    """Main class for the Smart Code Review tool."""
    
    def __init__(self, config_path=None):
        """Initialize the code review tool.
        
        Args:
            config_path (str, optional): Path to configuration file.
        """
        self.config = load_config(config_path)
        self.code_parser = CodeParser(self.config.get('general', {}))
        self.analyzer = CodeAnalyzer(self.config)
        self.report_generator = ReportGenerator()
    
    def review_file(self, file_path):
        """Review a single file.
        
        Args:
            file_path (str): Path to the file to review.
            
        Returns:
            dict: Review results for the file.
        """
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        # Check if file should be excluded
        if self._should_exclude_file(file_path):
            logger.info(f"Skipping excluded file: {file_path}")
            return None
        
        # Get file content
        content = self.code_parser.parse_file(file_path)
        if content is None:
            logger.error(f"Could not read file: {file_path}")
            return None
        
        # Determine language
        language = self.code_parser.get_language_from_file(file_path)
        if not language:
            logger.warning(f"Unsupported file type: {file_path}")
            return None
        
        logger.info(f"Reviewing {language} file: {file_path}")
        
        # Initialize result
        result = {
            'file_path': file_path,
            'language': language,
            'findings': []
        }
        
        # Run the analyzer
        try:
            findings = self.analyzer.analyze(file_path, content)
            result['findings'] = findings
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {str(e)}")
        
        # Add code snippets to findings
        if result['findings']:
            self.report_generator.add_code_snippets_to_findings([result])
            logger.info(f"Found {len(result['findings'])} issues in {file_path}")
        else:
            logger.info(f"No issues found in {file_path}")
        
        return result
    
    def review_directory(self, directory, recursive=True):
        """Review all applicable files in a directory.
        
        Args:
            directory (str): Path to the directory to review.
            recursive (bool): Whether to scan subdirectories.
            
        Returns:
            list: Review results for all files.
        """
        if not os.path.isdir(directory):
            logger.error(f"Directory not found: {directory}")
            return []
        
        logger.info(f"Reviewing directory: {directory}")
        
        # Get source files
        files = []
        if recursive:
            files = self.code_parser.get_source_files(directory)
        else:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path) and not self._should_exclude_file(item_path):
                    if self.code_parser._is_source_file(item_path):
                        files.append(item_path)
        
        if not files:
            logger.warning(f"No source files found in {directory}")
            return []
        
        logger.info(f"Found {len(files)} source files to review")
        
        # Review each file
        results = []
        for file_path in files:
            result = self.review_file(file_path)
            if result:
                results.append(result)
        
        return results
    
    def generate_report(self, results, format='html', output_path=None):
        """Generate a report from review results.
        
        Args:
            results (list): List of review results.
            format (str): Report format ('html', 'markdown', 'json').
            output_path (str, optional): Path to save the report.
            
        Returns:
            str: Path to the generated report.
        """
        if not results:
            logger.warning("No results to generate report")
            return None
        
        logger.info(f"Generating {format} report for {len(results)} files")
        
        # Generate and save the report
        report_path = self.report_generator.generate_report(results, format, output_path)
        
        if report_path:
            logger.info(f"Report saved to {report_path}")
        else:
            logger.error("Failed to generate report")
        
        return report_path
    
    def _should_exclude_file(self, file_path):
        """Check if a file should be excluded from review.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            bool: True if file should be excluded, False otherwise.
        """
        # Check against excluded directories
        excluded_dirs = self.config.get('general', {}).get('excluded_directories', [])
        for excluded_dir in excluded_dirs:
            if excluded_dir in file_path.split(os.sep):
                return True
        
        # Check against excluded file patterns
        excluded_patterns = self.config.get('general', {}).get('excluded_file_patterns', [])
        filename = os.path.basename(file_path)
        for pattern in excluded_patterns:
            if self.code_parser._match_pattern(filename, pattern):
                return True
        
        return False

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Smart Code Review - AI-powered local code review tool')
    
    # Main operation modes
    parser.add_argument('path', nargs='?', default='.',
                      help='Path to file or directory to review (default: current directory)')
    parser.add_argument('--config', '-c', 
                      help='Path to configuration file')
    
    # Output options
    parser.add_argument('--format', '-f', choices=['html', 'markdown', 'json'], default='html',
                      help='Report format (default: html)')
    parser.add_argument('--output', '-o', 
                      help='Output file for the report')
    parser.add_argument('--verbose', '-v', action='count', default=0,
                      help='Increase verbosity (can be used multiple times)')
    
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Set logging level based on verbosity
    if args.verbose >= 2:
        logging.getLogger('smart_code_review').setLevel(logging.DEBUG)
    elif args.verbose >= 1:
        logging.getLogger('smart_code_review').setLevel(logging.INFO)
    else:
        logging.getLogger('smart_code_review').setLevel(logging.WARNING)
    
    # Initialize code review assistant
    review_assistant = SmartCodeReview(args.config)
    
    # Determine operation mode and run review
    start_time = time.time()
    
    if os.path.isfile(args.path):
        # Review a single file
        results = [review_assistant.review_file(args.path)]
        results = [r for r in results if r]  # Filter None results
    elif os.path.isdir(args.path):
        # Review a directory
        results = review_assistant.review_directory(args.path)
    else:
        logger.error(f"Invalid path: {args.path}")
        sys.exit(1)
    
    # Generate report
    if results:
        report_path = review_assistant.generate_report(results, args.format, args.output)
        
        if report_path:
            print(f"\nReview completed. Report saved to: {report_path}")
            
            # Print summary
            total_findings = sum(len(result['findings']) for result in results)
            print(f"\nSummary:")
            print(f"- Files analyzed: {len(results)}")
            print(f"- Issues found: {total_findings}")
            
            # Count by severity
            severity_counts = {}
            for result in results:
                for finding in result['findings']:
                    severity = finding.get('severity', 'info')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity in ['high', 'medium', 'low', 'info']:
                if severity in severity_counts:
                    print(f"- {severity.capitalize()} issues: {severity_counts[severity]}")
        else:
            print("Failed to generate report.")
            sys.exit(1)
    else:
        print("No results to report.")
    
    elapsed_time = time.time() - start_time
    print(f"\nAnalysis completed in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()