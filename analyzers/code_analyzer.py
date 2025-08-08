# Combined analyzer (security, style, static, ML)
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import ast
import logging
import pickle
import os
from pathlib import Path
from analyzers.analyzer_base import AnalyzerBase

logger = logging.getLogger(__name__)

class CodeAnalyzer(AnalyzerBase):
    """Combined code analyzer that performs security, style, and static analysis."""
    
    def __init__(self, config=None):
        """Initialize the code analyzer with configuration.
        
        Args:
            config (dict): Configuration parameters.
        """
        super().__init__(config)
        
        # Configuration for different analyzer types
        self.security_config = self.config.get('security', {})
        self.style_config = self.config.get('style', {})
        self.static_config = self.config.get('static', {})
        self.ml_config = self.config.get('ml', {})
        
        # Load security patterns
        self.security_patterns = self._load_security_patterns()
        
        # Load style rules
        self.style_rules = self._load_style_rules()
        
        # Load ML model if available and enabled
        self.ml_enabled = self.ml_config.get('enabled', False)
        self.ml_model = None
        
        if self.ml_enabled:
            self._load_ml_model()
    
    def get_language(self, file_path):
        """Determine the programming language based on file extension.
        
        Args:
            file_path (str): Path to the file being analyzed.
            
        Returns:
            str: Language identifier or None if unsupported.
        """
        if not file_path:
            return None
            
        # Handle case where file_path might be just a filename or "pasted_code"
        if file_path in ['pasted_code', 'uploaded_file']:
            # For pasted code, we'll assume Python for now
            # In the future, this could be enhanced with language detection
            return 'python'
        
        # Extract file extension
        _, ext = os.path.splitext(file_path.lower())
        
        # Map extensions to languages
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift'
        }
        
        return language_map.get(ext)
    
    def analyze(self, file_path, file_content):
        """Analyze the file for various issues.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            
        Returns:
            list: List of findings with severity and description.
        """
        findings = []
        
        # Determine language
        language = self.get_language(file_path)
        if not language:
            logger.debug(f"Unsupported file type: {file_path}")
            return findings
        
        # Security analysis
        security_findings = self._analyze_security(file_path, file_content, language)
        findings.extend(security_findings)
        
        # Style analysis
        style_findings = self._analyze_style(file_path, file_content, language)
        findings.extend(style_findings)
        
        # Static analysis
        static_findings = self._analyze_static(file_path, file_content, language)
        findings.extend(static_findings)
        
        # ML-based pattern analysis
        if self.ml_enabled and self.ml_model is not None:
            ml_findings = self._analyze_ml_patterns(file_path, file_content, language)
            findings.extend(ml_findings)
        
        return findings
    
    def _load_security_patterns(self):
        """Load security patterns for different languages.
        
        Returns:
            dict: Security patterns organized by language and vulnerability type.
        """
        # Define common security patterns
        patterns = {
            'python': {
                'sql_injection': [
                    {
                        'pattern': r'execute\([\'"`].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*?[\'"]\s*%',
                        'message': 'Potential SQL injection vulnerability with string formatting',
                        'severity': 'high'
                    },
                    {
                        'pattern': r'execute\([\'"`].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*?[\'"]\s*\+',
                        'message': 'Potential SQL injection vulnerability with string concatenation',
                        'severity': 'high'
                    },
                    {
                        'pattern': r'[\'"`].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*?[\'"]\s*\+',
                        'message': 'Potential SQL injection vulnerability - SQL query built with string concatenation',
                        'severity': 'high'
                    }
                ],
                'os_command_injection': [
                    {
                        'pattern': r'os\.system\(.*?\+',
                        'message': 'Potential OS command injection with string concatenation',
                        'severity': 'high'
                    },
                    {
                        'pattern': r'subprocess\.(?:call|Popen|run)\(.*?shell\s*=\s*True',
                        'message': 'Shell=True may lead to command injection vulnerabilities',
                        'severity': 'high'
                    }
                ],
                'hardcoded_secrets': [
                    {
                        'pattern': r'(?i)(?:password|passwd|pwd|secret|key|token|api_?key)\s*=\s*[\'"`][^\'"`]{8,}[\'"`]',
                        'message': 'Possible hardcoded credential or secret',
                        'severity': 'high'
                    }
                ]
            },
            'javascript': {
                'xss': [
                    {
                        'pattern': r'(?:\.innerHTML|\.outerHTML)\s*=',
                        'message': 'Potential XSS vulnerability with innerHTML assignment',
                        'severity': 'high'
                    },
                    {
                        'pattern': r'document\.write\([^)]*\)',
                        'message': 'Potential XSS vulnerability with document.write',
                        'severity': 'high'
                    }
                ],
                'hardcoded_secrets': [
                    {
                        'pattern': r'(?i)(?:password|passwd|pwd|secret|key|token|api_?key)\s*=\s*[\'"`][^\'"`]{8,}[\'"`]',
                        'message': 'Possible hardcoded credential or secret',
                        'severity': 'high'
                    }
                ]
            }
        }
        
        # Add custom patterns from config if available
        custom_patterns = self.security_config.get('custom_patterns', {})
        for language, language_patterns in custom_patterns.items():
            if language not in patterns:
                patterns[language] = {}
            for check_type, check_patterns in language_patterns.items():
                if check_type not in patterns[language]:
                    patterns[language][check_type] = []
                patterns[language][check_type].extend(check_patterns)
        
        return patterns
    
    def _load_style_rules(self):
        """Load style rules for different languages.
        
        Returns:
            dict: Style rules organized by language.
        """
        # Define common style rules
        rules = {
            'python': [
                {
                    'pattern': r'^\s*def\s+(?:[A-Z]|[a-z]+[A-Z])[a-zA-Z0-9_]*\s*\(',
                    'message': 'Function names should be lowercase with underscores',
                    'severity': 'low'
                },
                {
                    'pattern': r'^\s*class\s+[a-z]',
                    'message': 'Class names should be CamelCase (start with uppercase)',
                    'severity': 'low'
                },
                {
                    'pattern': r'^\s*[a-zA-Z0-9_]+\s*=\s*[\'"].*[\'"]$',
                    'message': 'Consider using constants (UPPERCASE) for string literals',
                    'severity': 'low'
                },
                {
                    'pattern': r'^\s*if\s+len\(',
                    'message': 'Better to use "if sequence:" instead of "if len(sequence):"',
                    'severity': 'low'
                }
            ],
            'javascript': [
                {
                    'pattern': r'var\s+',
                    'message': 'Consider using let/const instead of var',
                    'severity': 'low'
                },
                {
                    'pattern': r'==(?!=)',
                    'message': 'Use === instead of == for comparison',
                    'severity': 'medium'
                },
                {
                    'pattern': r'!=(?!=)',
                    'message': 'Use !== instead of != for comparison',
                    'severity': 'medium'
                }
            ]
        }
        
        # Add custom style rules from config
        custom_rules = self.style_config.get('custom_rules', {})
        for language, language_rules in custom_rules.items():
            if language not in rules:
                rules[language] = []
            rules[language].extend(language_rules)
        
        return rules
    
    def _load_ml_model(self):
        """Load machine learning model for pattern analysis."""
        model_path = self.ml_config.get('model_path', 'data/models/pattern_model.pkl')
        
        try:
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                logger.info(f"Loaded ML model from {model_path}")
            else:
                logger.warning(f"ML model not found at {model_path}, initializing empty model")
                # Initialize an empty model for collecting patterns
                self.ml_model = {'patterns': {}}
        except Exception as e:
            logger.error(f"Error loading ML model: {str(e)}")
            self.ml_model = None
    
    def _analyze_security(self, file_path, file_content, language):
        """Analyze the file for security vulnerabilities.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            language (str): Language of the file.
            
        Returns:
            list: List of security findings.
        """
        findings = []
        
        # Skip analysis if language is not supported
        if language not in self.security_patterns:
            return findings
        
        # Get security checks configuration
        enabled_checks = self.security_config.get('enabled_checks', {
            'sql_injection': True,
            'xss': True,
            'hardcoded_secrets': True,
            'insecure_functions': True,
            'os_command_injection': True
        })
        
        # Apply security patterns for the language
        language_patterns = self.security_patterns[language]
        lines = file_content.splitlines()
        
        for check_type, patterns in language_patterns.items():
            # Skip if check type is disabled in config
            if not enabled_checks.get(check_type, True):
                continue
                
            for pattern_data in patterns:
                regex = re.compile(pattern_data['pattern'])
                
                # Check each line for the pattern
                for i, line in enumerate(lines):
                    if regex.search(line):
                        findings.append({
                            'type': 'security',
                            'severity': pattern_data['severity'],
                            'check': check_type,
                            'message': pattern_data['message'],
                            'line': i + 1,
                            'column': 1,
                            'file': file_path,
                            'code': line.strip()
                        })
        
        return findings
    
    def _analyze_style(self, file_path, file_content, language):
        """Analyze the file for style issues.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            language (str): Language of the file.
            
        Returns:
            list: List of style findings.
        """
        findings = []
        
        # Skip analysis if language is not supported
        if language not in self.style_rules:
            return findings
        
        # Apply style rules for the language
        rules = self.style_rules[language]
        lines = file_content.splitlines()
        
        for rule in rules:
            regex = re.compile(rule['pattern'])
            
            # Check each line for the pattern
            for i, line in enumerate(lines):
                if regex.search(line):
                    findings.append({
                        'type': 'style',
                        'severity': rule['severity'],
                        'message': rule['message'],
                        'line': i + 1,
                        'column': 1,
                        'file': file_path,
                        'code': line.strip()
                    })
        
        return findings
    
    def _analyze_static(self, file_path, file_content, language):
        """Analyze the file for static code issues.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            language (str): Language of the file.
            
        Returns:
            list: List of static analysis findings.
        """
        findings = []
        
        # For Python files, use AST to find issues
        if language == 'python':
            try:
                tree = ast.parse(file_content)
                
                # Check for unused variables
                if self.static_config.get('unused_variables', True):
                    findings.extend(self._check_unused_variables(tree, file_path))
                
                # Check for unreachable code
                if self.static_config.get('unreachable_code', True):
                    findings.extend(self._check_unreachable_code(tree, file_path))
                
            except SyntaxError as e:
                findings.append({
                    'type': 'static',
                    'severity': 'high',
                    'message': f'Syntax error: {str(e)}',
                    'line': e.lineno if hasattr(e, 'lineno') else 1,
                    'column': e.offset if hasattr(e, 'offset') else 1,
                    'file': file_path,
                    'code': e.text.strip() if hasattr(e, 'text') and e.text else ''
                })
            except Exception as e:
                logger.error(f"Error during static analysis of {file_path}: {str(e)}")
        
        # For JavaScript/TypeScript files, use simple regex checks
        elif language in ['javascript', 'typescript']:
            # Simple check for unused variables (this is a basic implementation)
            findings.extend(self._check_js_unused_variables(file_content.splitlines(), file_path))
        
        return findings
    
    def _check_unused_variables(self, tree, file_path):
        """Check for unused variables in Python code.
        
        Args:
            tree (ast.AST): AST of the Python code.
            file_path (str): Path to the file.
            
        Returns:
            list: Findings related to unused variables.
        """
        findings = []
        
        class UnusedVarVisitor(ast.NodeVisitor):
            def __init__(self):
                self.defined = {}
                self.used = set()
                
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    self.defined[node.id] = node.lineno
                elif isinstance(node.ctx, ast.Load):
                    self.used.add(node.id)
                self.generic_visit(node)
                
            def visit_arg(self, node):
                self.defined[node.arg] = node.lineno
                self.generic_visit(node)
                
            def get_unused(self):
                return {name: line for name, line in self.defined.items() 
                       if name not in self.used and not name.startswith('_')}
                
        visitor = UnusedVarVisitor()
        visitor.visit(tree)
        
        for name, line in visitor.get_unused().items():
            findings.append({
                'type': 'static',
                'severity': 'low',
                'message': f'Unused variable: {name}',
                'line': line,
                'column': 1,
                'file': file_path
            })
            
        return findings
    
    def _check_unreachable_code(self, tree, file_path):
        """Check for unreachable code in Python code.
        
        Args:
            tree (ast.AST): AST of the Python code.
            file_path (str): Path to the file.
            
        Returns:
            list: Findings related to unreachable code.
        """
        findings = []
        
        class UnreachableCodeVisitor(ast.NodeVisitor):
            def __init__(self):
                self.findings = []
                
            def visit_FunctionDef(self, node):
                has_return = False
                for i, stmt in enumerate(node.body):
                    # If we've seen a bare return or raise and there are more statements
                    if has_return and i < len(node.body) - 1:
                        self.findings.append({
                            'type': 'static',
                            'severity': 'medium',
                            'message': 'Unreachable code after return statement',
                            'line': node.body[i+1].lineno,
                            'column': 1
                        })
                        break
                        
                    if isinstance(stmt, ast.Return) and not stmt.value:
                        has_return = True
                    elif isinstance(stmt, ast.Raise):
                        has_return = True
                        
                self.generic_visit(node)
                
        visitor = UnreachableCodeVisitor()
        visitor.visit(tree)
        
        for finding in visitor.findings:
            finding['file'] = file_path
            findings.append(finding)
            
        return findings
    
    def _check_js_unused_variables(self, lines, file_path):
        """Simple check for potentially unused variables in JavaScript.
        
        Args:
            lines (list): Lines of code.
            file_path (str): Path to the file.
            
        Returns:
            list: Findings related to unused variables.
        """
        findings = []
        var_declarations = {}
        var_usages = set()
        
        # Find variable declarations
        var_pattern = re.compile(r'(?:var|let|const)\s+(\w+)\s*=')
        for i, line in enumerate(lines):
            for match in var_pattern.finditer(line):
                var_name = match.group(1)
                var_declarations[var_name] = i + 1
        
        # Find variable usages
        for i, line in enumerate(lines):
            for var_name in var_declarations:
                # Don't count the declaration line as usage
                if i + 1 != var_declarations[var_name] and re.search(r'\b' + re.escape(var_name) + r'\b', line):
                    var_usages.add(var_name)
        
        # Report unused variables
        for var_name, line_num in var_declarations.items():
            if var_name not in var_usages and not var_name.startswith('_'):
                findings.append({
                    'type': 'static',
                    'severity': 'low',
                    'message': f'Potentially unused variable: {var_name}',
                    'line': line_num,
                    'column': 1,
                    'file': file_path
                })
                
        return findings
    
    def _analyze_ml_patterns(self, file_path, file_content, language):
        """Analyze code using ML-based pattern detection.
        
        Args:
            file_path (str): Path to the file being analyzed.
            file_content (str): Content of the file.
            language (str): Language of the file.
            
        Returns:
            list: List of findings from ML pattern analysis.
        """
        findings = []
        
        # Skip if ML model is not available
        if self.ml_model is None:
            return findings
        
        try:
            # This is a simplified implementation of ML pattern detection
            # In a real implementation, you would extract features from the code
            # and use a trained model to detect patterns
            
            # Example: detect common code patterns based on frequency
            lines = file_content.splitlines()
            
            # Check for patterns in the ML model
            patterns = self.ml_model.get('patterns', {}).get(language, [])
            
            for pattern in patterns:
                regex = re.compile(pattern['pattern'])
                for i, line in enumerate(lines):
                    if regex.search(line):
                        findings.append({
                            'type': 'ml_pattern',
                            'severity': pattern.get('severity', 'medium'),
                            'message': pattern['message'],
                            'line': i + 1,
                            'column': 1,
                            'file': file_path,
                            'code': line.strip()
                        })
            
            # Learn from this file for future analysis
            self._learn_from_file(file_content, language)
            
        except Exception as e:
            logger.error(f"Error in ML pattern analysis: {str(e)}")
        
        return findings
    
    def _learn_from_file(self, file_content, language):
        """Learn patterns from a file for future analysis.
        
        Args:
            file_content (str): Content of the file.
            language (str): Language of the file.
        """
        # This is a simplified implementation
        # In a real implementation, this would update the ML model with new patterns
        pass
    
    def update_ml_model(self, feedback):
        """Update the ML model with feedback.
        
        Args:
            feedback (dict): Feedback about findings.
        """
        if self.ml_model is None:
            return
        
        # Update model based on feedback
        # This is a simplified implementation
        try:
            # Process feedback to improve model accuracy
            if feedback and isinstance(feedback, dict):
                # Example: adjust model weights based on feedback
                feedback_type = feedback.get('type', 'unknown')
                is_useful = feedback.get('useful', True)
                
                # Update model patterns (simplified)
                if hasattr(self.ml_model, 'update'):
                    self.ml_model.update(feedback_type, is_useful)
            
            # Save updated model
            if self.ml_config.get('model_path'):
                with open(self.ml_config.get('model_path'), 'wb') as f:
                    pickle.dump(self.ml_model, f)
        except Exception as e:
            logger.error(f"Error saving ML model: {str(e)}")