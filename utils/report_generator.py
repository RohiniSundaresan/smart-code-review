#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import logging
import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates code review reports in various formats."""
    
    def __init__(self):
        """Initialize report generator."""
        self.report_dir = "reports"
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def generate_report(self, results, format='html', output_path=None):
        """Generate a code review report.
        
        Args:
            results (list): List of review results for files.
            format (str): Report format ('html', 'markdown', 'json').
            output_path (str, optional): Path to save the report.
            
        Returns:
            str: Path to the generated report.
        """
        if not results:
            logger.warning("No results to generate report")
            return None
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        if not output_path:
            filename = f"code_review_{timestamp}"
            if format == 'html':
                output_path = os.path.join(self.report_dir, f"{filename}.html")
            elif format == 'markdown':
                output_path = os.path.join(self.report_dir, f"{filename}.md")
            elif format == 'json':
                output_path = os.path.join(self.report_dir, f"{filename}.json")
            else:
                logger.error(f"Unsupported report format: {format}")
                return None
        
        try:
            if format == 'html':
                self._generate_html_report(results, output_path)
            elif format == 'markdown':
                self._generate_markdown_report(results, output_path)
            elif format == 'json':
                self._generate_json_report(results, output_path)
            
            logger.info(f"Generated {format} report at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None
    
    def _generate_html_report(self, results, output_path):
        """Generate an HTML report.
        
        Args:
            results (list): List of review results for files.
            output_path (str): Path to save the report.
        """
        # Count findings by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results:
            for finding in result.get('findings', []):
                severity = finding.get('severity', 'info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        html = [
            '<!DOCTYPE html>',
            '<html>',
            '<head>',
            '    <title>Code Review Report</title>',
            '    <style>',
            '        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
            '        h1 { color: #333; }',
            '        h2 { color: #444; margin-top: 30px; }',
            '        .summary { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }',
            '        .file { margin-bottom: 30px; padding: 15px; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; }',
            '        .file-path { font-weight: bold; margin-bottom: 10px; }',
            '        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }',
            '        .high { border-color: #dc3545; }',
            '        .medium { border-color: #fd7e14; }',
            '        .low { border-color: #ffc107; }',
            '        .info { border-color: #0dcaf0; }',
            '        .code { font-family: monospace; background-color: #f7f7f7; padding: 10px; border-radius: 3px; overflow-x: auto; }',
            '        .severity-tag { display: inline-block; padding: 2px 8px; border-radius: 10px; color: white; font-size: 0.8em; }',
            '        .high-tag { background-color: #dc3545; }',
            '        .medium-tag { background-color: #fd7e14; }',
            '        .low-tag { background-color: #ffc107; color: #333; }',
            '        .info-tag { background-color: #0dcaf0; }',
            '    </style>',
            '</head>',
            '<body>',
            '    <h1>Code Review Report</h1>',
            '    <div class="summary">',
            '        <h2>Summary</h2>',
            f'        <p>Files analyzed: {len(results)}</p>',
            f'        <p>Total issues found: {sum(severity_counts.values())}</p>',
            f'        <p>High severity issues: {severity_counts.get("high", 0)}</p>',
            f'        <p>Medium severity issues: {severity_counts.get("medium", 0)}</p>',
            f'        <p>Low severity issues: {severity_counts.get("low", 0)}</p>',
            f'        <p>Info severity issues: {severity_counts.get("info", 0)}</p>',
            '        <p>Report generated on: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '</p>',
            '    </div>'
        ]
        
        # Add file results
        for result in results:
            file_path = result.get('file_path', '')
            findings = result.get('findings', [])
            
            if not findings:
                continue
            
            html.append(f'    <div class="file">')
            html.append(f'        <div class="file-path">{file_path}</div>')
            
            for finding in findings:
                severity = finding.get('severity', 'info')
                message = finding.get('message', '')
                line = finding.get('line', '')
                code = finding.get('code', '')
                
                html.append(f'        <div class="finding {severity}">')
                html.append(f'            <span class="severity-tag {severity}-tag">{severity.upper()}</span>')
                html.append(f'            <p><strong>{message}</strong> (Line {line})</p>')
                if code:
                    html.append(f'            <pre class="code">{code}</pre>')
                html.append(f'        </div>')
            
            html.append(f'    </div>')
        
        html.extend([
            '</body>',
            '</html>'
        ])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
    
    def _generate_markdown_report(self, results, output_path):
        """Generate a Markdown report.
        
        Args:
            results (list): List of review results for files.
            output_path (str): Path to save the report.
        """
        # Count findings by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results:
            for finding in result.get('findings', []):
                severity = finding.get('severity', 'info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        md = [
            '# Code Review Report',
            '',
            '## Summary',
            '',
            f'- Files analyzed: {len(results)}',
            f'- Total issues found: {sum(severity_counts.values())}',
            f'- High severity issues: {severity_counts.get("high", 0)}',
            f'- Medium severity issues: {severity_counts.get("medium", 0)}',
            f'- Low severity issues: {severity_counts.get("low", 0)}',
            f'- Info severity issues: {severity_counts.get("info", 0)}',
            f'- Report generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            ''
        ]
        
        # Add file results
        for result in results:
            file_path = result.get('file_path', '')
            findings = result.get('findings', [])
            
            if not findings:
                continue
            
            md.append(f'## {file_path}')
            md.append('')
            
            for finding in findings:
                severity = finding.get('severity', 'info')
                message = finding.get('message', '')
                line = finding.get('line', '')
                code = finding.get('code', '')
                
                md.append(f'### {severity.upper()}: {message}')
                md.append(f'- Line: {line}')
                if code:
                    md.append('```')
                    md.append(code)
                    md.append('```')
                md.append('')
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md))
    
    def _generate_json_report(self, results, output_path):
        """Generate a JSON report.
        
        Args:
            results (list): List of review results for files.
            output_path (str): Path to save the report.
        """
        report = {
            'summary': {
                'files_analyzed': len(results),
                'total_issues': sum(len(result.get('findings', [])) for result in results),
                'generated_at': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            'results': results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    
    def add_code_snippets_to_findings(self, results):
        """Add code snippets to findings.
        
        Args:
            results (list): List of review results to update with code snippets.
        """
        for result in results:
            file_path = result.get('file_path')
            if not file_path or not os.path.exists(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                    lines = file.readlines()
                    
                    for finding in result.get('findings', []):
                        line_num = finding.get('line', 0)
                        if 0 < line_num <= len(lines):
                            # Add the code from the line if not already added
                            if 'code' not in finding or not finding['code']:
                                finding['code'] = lines[line_num - 1].rstrip()
                                
                            # Add context lines (1 before and 1 after)
                            context = []
                            if line_num > 1:
                                context.append(f"{line_num-1}: {lines[line_num - 2].rstrip()}")
                            context.append(f"{line_num}: {lines[line_num - 1].rstrip()}")
                            if line_num < len(lines):
                                context.append(f"{line_num+1}: {lines[line_num].rstrip()}")
                                
                            finding['context'] = context
            except Exception as e:
                logger.error(f"Error adding code snippets for {file_path}: {str(e)}")