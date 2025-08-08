# base class for all analyzers
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from pathlib import Path

# Configure logger for this module
logging.getLogger(__name__)

class AnalyzerBase:
    """Base class for all code analyzers."""
    
    def __init__(self, config=None):
        """Initialize the analyzer with configuration.
        
        Args:
            config (dict): Configuration parameters.
        """
        self.config = config or {}
        
    def analyze(self, file_path, file_content):
        """Analyze the file and return findings.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            
        Returns:
            list: List of findings.
        """
        # This method should be implemented by subclasses
        raise NotImplementedError("Subclasses must implement analyze()")
    
    def get_language(self, file_path):
        """Determine the programming language of a file based on its extension.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            str: Language name or None if not supported.
        """
        ext = Path(file_path).suffix.lower()
        
        if ext in ['.py']:
            return 'python'
        elif ext in ['.js', '.jsx']:
            return 'javascript'
        elif ext in ['.ts', '.tsx']:
            return 'typescript'
        elif ext in ['.html', '.htm']:
            return 'html'
        elif ext in ['.css']:
            return 'css'
        elif ext in ['.java']:
            return 'java'
        elif ext in ['.c', '.cpp', '.h', '.hpp']:
            return 'c_cpp'
        elif ext in ['.go']:
            return 'go'
        elif ext in ['.rb']:
            return 'ruby'
        elif ext in ['.php']:
            return 'php'
        
        return None