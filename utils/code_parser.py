#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import fnmatch
from pathlib import Path

logger = logging.getLogger(__name__)

class CodeParser:
    """Utility class for parsing and handling code files."""
    
    def __init__(self, config=None):
        """Initialize code parser with configuration.
        
        Args:
            config (dict): Configuration parameters.
        """
        self.config = config or {}
        self.excluded_dirs = self.config.get('excluded_directories', ['node_modules', '__pycache__', 'venv', '.git', '.idea'])
        self.excluded_patterns = self.config.get('excluded_file_patterns', ['*.min.js', '*.map'])
        self.source_extensions = self.config.get('source_extensions', [
            '.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.java', '.c', '.cpp', '.h', '.go', '.rb', '.php'
        ])
    
    def parse_file(self, file_path):
        """Parse and read a code file.
        
        Args:
            file_path (str): Path to the file to parse.
            
        Returns:
            str: File content or None if file cannot be read.
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                return file.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            return None
    
    def get_source_files(self, directory):
        """Get all source code files in a directory.
        
        Args:
            directory (str): Directory to scan for source files.
            
        Returns:
            list: List of source file paths.
        """
        source_files = []
        
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            
            for file in files:
                # Skip files that match excluded patterns
                if any(fnmatch.fnmatch(file, pattern) for pattern in self.excluded_patterns):
                    continue
                    
                file_path = os.path.join(root, file)
                if self._is_source_file(file_path):
                    source_files.append(file_path)
        
        return source_files
    
    def _is_source_file(self, file_path):
        """Check if a file is a source code file.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            bool: True if file is a source code file, False otherwise.
        """
        ext = Path(file_path).suffix.lower()
        return ext in self.source_extensions
    
    def get_language_from_file(self, file_path):
        """Determine the programming language of a file.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            str: Language name or None if not supported.
        """
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.html': 'html',
            '.css': 'css',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php'
        }
        
        return language_map.get(ext)
    
    def _match_pattern(self, filename, pattern):
        """Check if a filename matches a pattern.
        
        Args:
            filename (str): Filename to check.
            pattern (str): Pattern to match against.
            
        Returns:
            bool: True if filename matches pattern, False otherwise.
        """
        return fnmatch.fnmatch(filename, pattern)