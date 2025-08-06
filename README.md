# Smart Code Review

An AI-powered local code review tool designed to identify security vulnerabilities, style issues, and code quality problems in your codebase. 

## Overview

Smart Code Review is a standalone tool that analyzes your code locally for:

- **Security vulnerabilities** - SQL injection, XSS, hardcoded secrets, command injection
- **Style issues** - Enforces coding standards and best practices
- **Static analysis** - Identifies unused variables, unreachable code, and other issues
- **ML-based pattern detection** - Learns from your code to detect recurring patterns

The tool supports multiple programming languages with specialized rules for Python and JavaScript.

## Features

- **Local execution** - All analysis happens on your machine, no code sent to external servers
- **Multiple language support** - Primary support for Python and JavaScript, with extensibility for others
- **Customizable configuration** - Adjust rules, thresholds, and checks via config file
- **Multiple output formats** - Generate reports in HTML, Markdown, or JSON
- **Machine learning capability** - Improves detection over time

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/smart-code-review.git

# Navigate to the directory
cd smart-code-review

# Install dependencies
pip install -r requirements.txt
```

## Usage Examples

```bash
# Analyze a single file
python main.py path/to/your/file.py

# Analyze a directory
python main.py path/to/your/project/

# Use a custom config file
python main.py path/to/your/project/ --config custom_config.json

# Output as JSON
python main.py path/to/your/project/ --format json

# Increase verbosity for more detailed logs
python main.py path/to/your/project/ --verbose
```

## Configuration

Smart Code Review can be configured via a JSON configuration file. Here's a sample configuration:

```json
{
  "general": {
    "excluded_directories": ["node_modules", "__pycache__", "venv", ".git", ".idea"],
    "excluded_file_patterns": ["*.min.js", "*.map"]
  },
  "security": {
    "enabled_checks": {
      "sql_injection": true,
      "xss": true,
      "hardcoded_secrets": true,
      "insecure_functions": true,
      "os_command_injection": true
    },
    "severity_threshold": "medium"
  },
  "style": {
    "enabled": true
  },
  "static": {
    "unused_variables": true,
    "unreachable_code": true
  },
  "ml": {
    "enabled": true,
    "model_path": "data/models/pattern_model.pkl"
  }
}
```

## Supported Analysis Types

### Security Analysis

Detects various security vulnerabilities including:

- SQL Injection vulnerabilities
- Cross-Site Scripting (XSS)
- Hardcoded credentials and secrets
- OS command injection
- Insecure function usage

### Style Analysis

Enforces coding standards like:

- Proper naming conventions
- Consistent syntax usage
- Code formatting issues
- Best practices for the language

### Static Analysis

Finds code quality issues:

- Unused variables and imports
- Unreachable code
- Syntax errors
- Potential bugs

### Machine Learning Analysis

Learns patterns from your code to detect:

- Recurring issues
- Custom patterns specific to your codebase
- Unusual code constructs

## Project Structure

```
smart-code-review/
├── analyzers/
│   ├── __init__.py
│   ├── analyzer_base.py
│   └── code_analyzer.py
├── docs/
│   ├── developer_guide.md
│   └── user_guide.md
├── tests/
│   ├── __init__.py
│   ├── test_analyzers.py
│   ├── test_ml.py
│   └── test_utils.py
├── utils/
│   ├── __init__.py
│   ├── code_parser.py
│   └── report_generator.py
├── config.json
├── main.py
├── README.md
└── requirements.txt
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- List any libraries or tools that inspired this project
- Credits for any third-party code or assets used