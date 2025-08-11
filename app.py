#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Smart Code Review - Web UI
Flask web application for uploading and reviewing code files
"""

import os
import json
import tempfile
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for

# Import your existing components
from analyzers.code_analyzer import CodeAnalyzer
from ml.simple_feedback import SimpleFeedback, add_simple_feedback_to_findings
from utils.report_generator import ReportGenerator

app = Flask(__name__)
app.secret_key = 'smart-code-review-secret-key'  # Change this in production
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'py', 'js', 'ts', 'jsx', 'tsx', 'java', 'cpp', 'c', 'h', 'hpp', 
    'cs', 'php', 'rb', 'go', 'rs', 'swift', 'kt', 'scala', 'txt'
}

# Global instances
analyzer = None
feedback_system = None
report_generator = None

def init_components():
    """Initialize analyzer and feedback system."""
    global analyzer, feedback_system, report_generator
    
    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except:
        # Default config if file not found
        config = {
            "security": {"enabled_checks": {"hardcoded_secrets": True}},
            "style": {"enabled": True},
            "static": {"unused_variables": True}
        }
    
    analyzer = CodeAnalyzer(config)
    feedback_system = SimpleFeedback("web_feedback.json")
    report_generator = ReportGenerator()

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with upload form."""
    return render_template('index.html')



def generate_enhanced_summary(filename, file_content, findings, adjusted_findings):
    """Generate enhanced summary with recommendations and insights."""
    
    # Count findings by type
    security_count = len([f for f in adjusted_findings if f.get('type') == 'security'])
    style_count = len([f for f in adjusted_findings if f.get('type') == 'style'])
    static_count = len([f for f in adjusted_findings if f.get('type') == 'static'])
    
    # Count by severity
    high_severity = len([f for f in adjusted_findings if f.get('severity') == 'high'])
    medium_severity = len([f for f in adjusted_findings if f.get('severity') == 'medium'])
    low_severity = len([f for f in adjusted_findings if f.get('severity') == 'low'])
    
    # Calculate quality score
    lines_of_code = len(file_content.split('\n'))
    quality_score = ((lines_of_code - len(adjusted_findings)) / lines_of_code * 100) if lines_of_code > 0 else 100
    
    # Determine priority focus
    priority_focus = "security" if security_count > 0 else "static" if static_count > 0 else "style" if style_count > 0 else "none"
    
    # Generate recommendations
    recommendations = []
    if security_count > 0:
        recommendations.append({
            'priority': 1,
            'type': 'security',
            'title': 'Address Security Vulnerabilities',
            'description': 'Fix hardcoded credentials, SQL injection risks, and other security issues immediately.',
            'count': security_count
        })
    
    if static_count > 0:
        recommendations.append({
            'priority': 2 if security_count > 0 else 1,
            'type': 'static',
            'title': 'Fix Code Structure Issues',
            'description': 'Remove unused variables, fix imports, and optimize code structure.',
            'count': static_count
        })
    
    if style_count > 0:
        recommendations.append({
            'priority': len(recommendations) + 1,
            'type': 'style',
            'title': 'Improve Code Style',
            'description': 'Follow coding conventions, add documentation, and improve readability.',
            'count': style_count
        })
    
    # Basic summary
    summary = {
        'filename': filename,
        'total_findings': len(findings),
        'adjusted_findings': len(adjusted_findings),
        'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'file_size': len(file_content),
        'lines_of_code': lines_of_code,
        
        # Enhanced data
        'quality_score': round(quality_score, 1),
        'security_count': security_count,
        'style_count': style_count,
        'static_count': static_count,
        'high_severity': high_severity,
        'medium_severity': medium_severity,
        'low_severity': low_severity,
        'priority_focus': priority_focus,
        'recommendations': recommendations
    }
    
    return summary

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload with improved error handling and response."""
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400
    
    if not allowed_file(file.filename):
        return jsonify({
            'success': False,
            'error': f'Invalid file type. Supported: {", ".join(ALLOWED_EXTENSIONS)}'
        }), 400
        
    try:
        # Secure the filename
        filename = secure_filename(file.filename)
        
        # Read file content
        file_content = file.read().decode('utf-8')
        
        # Initialize components if needed
        if analyzer is None:
            init_components()
            
        # Analyze the code
        findings = analyzer.analyze(filename, file_content)
        
        # Apply ML feedback learning
        adjusted_findings = add_simple_feedback_to_findings(findings, feedback_system)
        
        # Get enhanced analysis summary
        summary = generate_enhanced_summary(filename, file_content, findings, adjusted_findings)
        
        # Store analysis data in session for download
        from flask import session
        session['last_analysis'] = {
            'findings': adjusted_findings,
            'summary': summary,
            'file_content': file_content
        }
        
        return jsonify({
            'success': True,
            'redirect': url_for('results')
        })
        
    except UnicodeDecodeError:
        return jsonify({
            'success': False,
            'error': 'File must be a text file with UTF-8 encoding'
        }), 400
    except Exception as e:
        print(f"Upload error: {str(e)}")  # Log the error
        return jsonify({
            'success': False,
            'error': 'An error occurred while processing the file'
        }), 500

@app.route('/results')
def results():
    """Display analysis results."""
    from flask import session
    analysis = session.get('last_analysis')
    if not analysis:
        flash('No analysis results found')
        return redirect(url_for('index'))
        
    return render_template('results.html',
                         findings=analysis['findings'],
                         summary=analysis['summary'],
                         file_content=analysis['file_content'])

@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    """Handle pasted code analysis."""
    code_text = request.form.get('code_text', '').strip()
    filename = request.form.get('filename', '').strip()
    language = request.form.get('language', 'auto')
    
    if not code_text:
        flash('Please paste some code to analyze')
        return redirect(url_for('index'))
    
    # Validate code length
    if len(code_text) > 100000:  # 100KB limit
        flash('Code is too large. Please keep it under 100KB for optimal performance.')
        return redirect(url_for('index'))
    
    # Generate filename if not provided
    if not filename:
        language_extensions = {
            'python': 'py',
            'javascript': 'js',
            'typescript': 'ts',
            'java': 'java',
            'cpp': 'cpp',
            'c': 'c',
            'csharp': 'cs',
            'php': 'php',
            'ruby': 'rb',
            'go': 'go',
            'rust': 'rs',
            'swift': 'swift',
            'kotlin': 'kt',
            'scala': 'scala'
        }
        
        # If language is 'auto', default to Python for analysis
        if language == 'auto':
            ext = 'py'  # Default to Python when auto-detect is selected
        else:
            ext = language_extensions.get(language, 'py')  # Default to .py instead of .txt
        
        filename = f"pasted_code.{ext}"
    
    # Ensure filename is safe
    filename = secure_filename(filename) or 'pasted_code.txt'
    
    try:
        # Analyze the pasted code
        findings = analyzer.analyze(filename, code_text)
        
        # Apply ML feedback learning
        adjusted_findings = add_simple_feedback_to_findings(findings, feedback_system)
        
        # Get enhanced analysis summary
        summary = generate_enhanced_summary(filename, code_text, findings, adjusted_findings)
        
        # Store analysis data in session for download
        from flask import session
        session['last_analysis'] = {
            'findings': adjusted_findings,
            'summary': summary,
            'file_content': code_text
        }
        
        return render_template('results.html', 
                             findings=adjusted_findings, 
                             summary=summary,
                             file_content=code_text)
    
    except Exception as e:
        flash(f'Analysis failed: {str(e)}')
        return redirect(url_for('index'))

@app.route('/feedback', methods=['POST'])
def record_feedback():
    """Record user feedback for ML learning."""
    data = request.get_json()
    finding_type = data.get('finding_type')
    useful = data.get('useful', True)
    
    if finding_type:
        feedback_system.record_feedback(finding_type, useful)
        return jsonify({'status': 'success', 'message': 'Feedback recorded'})
    
    return jsonify({'status': 'error', 'message': 'Invalid feedback data'})

@app.route('/stats')
def get_stats():
    """Get ML feedback statistics."""
    stats = feedback_system.get_stats()
    return jsonify(stats)

@app.route('/demo')
def demo():
    """Demo page with sample code."""
    sample_code = '''# Sample Python code with issues
import os
import sys

# Security issue: hardcoded credential
API_KEY = "sk-1234567890abcdef"

# Style issue: function name should be lowercase
def BadFunctionName():
    unused_var = "not used"  # Static issue: unused variable
    password = "admin123"    # Security issue: hardcoded password
    return "hello world"

# Missing docstring for class
class MyClass:
    def __init__(self):
        self.data = []
    
    def process_data(self):
        for i in range(10):
            self.data.append(i * 2)
'''
    
    # Analyze sample code
    findings = analyzer.analyze("sample.py", sample_code)
    adjusted_findings = add_simple_feedback_to_findings(findings, feedback_system)
    
    # Get enhanced analysis summary
    summary = generate_enhanced_summary("sample.py", sample_code, findings, adjusted_findings)
    
    # Store demo analysis data in session
    from flask import session
    session['last_analysis'] = {
        'findings': adjusted_findings,
        'summary': summary,
        'file_content': sample_code
    }
    
    return render_template('results.html', 
                         findings=adjusted_findings, 
                         summary=summary,
                         file_content=sample_code,
                         is_demo=True)

@app.route('/download/<report_format>')
def download_report(report_format):
    """Download analysis report in specified format."""
    from flask import session
    
    # Get analysis data from session
    analysis_data = session.get('last_analysis')
    if not analysis_data:
        flash('No analysis data available for download')
        return redirect(url_for('index'))
    
    findings = analysis_data['findings']
    summary = analysis_data['summary']
    filename = summary.get('filename', 'code_analysis')
    
    # Generate report based on format
    if report_format == 'json':
        return download_json_report(findings, summary, filename)
    elif report_format == 'html':
        return download_html_report(findings, summary, filename)
    elif report_format == 'csv':
        return download_csv_report(findings, summary, filename)
    else:
        flash('Unsupported report format')
        return redirect(url_for('index'))

def download_json_report(findings, summary, filename):
    """Generate and download JSON report."""
    report_data = {
        'analysis_summary': summary,
        'findings': findings,
        'generated_at': datetime.now().isoformat(),
        'report_version': '1.0'
    }
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8')
    json.dump(report_data, temp_file, indent=2, ensure_ascii=False)
    temp_file.close()
    
    try:
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"{filename}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mimetype='application/json'
        )
    finally:
        # Clean up the temporary file after sending
        try:
            os.unlink(temp_file.name)
        except:
            pass

def download_html_report(findings, summary, filename):
    """Generate and download HTML report with fixed CSS handling."""
    # Build CSS styles without f-strings
    css_rules = []
    css_rules.append('body { font-family: Arial, sans-serif; margin: 40px; }')
    css_rules.append('.header { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }')
    css_rules.append('.finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }')
    css_rules.append('.severity-high { border-left: 5px solid #dc3545; }')
    css_rules.append('.severity-medium { border-left: 5px solid #ffc107; }')
    css_rules.append('.severity-low { border-left: 5px solid #28a745; }')
    css_rules.append('.type-badge { padding: 5px 10px; border-radius: 3px; color: white; font-size: 0.8em; }')
    css_rules.append('.security { background: #dc3545; }')
    css_rules.append('.style { background: #007bff; }')
    css_rules.append('.static { background: #28a745; }')
    css_rules.append('.code { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }')
    
    css_content = '\n'.join(css_rules)
    
    # Build HTML without f-strings
    html_parts = []
    html_parts.append('<!DOCTYPE html>')
    html_parts.append('<html>')
    html_parts.append('<head>')
    html_parts.append('<title>Smart Code Reviewer Report - ' + filename + '</title>')
    html_parts.append('<style>')
    html_parts.append(css_content)
    html_parts.append('</style>')
    html_parts.append('</head>')
    html_parts.append('<body>')
    html_parts.append('<div class="header">')
    html_parts.append('<h1>Smart Code Reviewer Report</h1>')
    html_parts.append('<p><strong>File:</strong> ' + summary.get('filename', filename) + '</p>')
    html_parts.append('<p><strong>Generated:</strong> ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '</p>')
    html_parts.append('<p><strong>Issues Found:</strong> ' + str(len(findings)) + '</p>')
    html_parts.append('</div>')
    html_parts.append('<h2>Analysis Results</h2>')
    
    if findings:
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'low')
            finding_type = finding.get('type', 'unknown')
            type_title = finding.get('type', 'Unknown').title()
            severity_title = finding.get('severity', 'Unknown').title()
            message = finding.get('message', 'No description')
            line = finding.get('line', 'Unknown')
            
            html_parts.append('<div class="finding severity-' + severity + '">')
            html_parts.append('<h3>Finding #' + str(i) + '</h3>')
            html_parts.append('<span class="type-badge ' + finding_type + '">' + type_title + '</span>')
            html_parts.append('<span class="type-badge" style="background: #6c757d;">Severity: ' + severity_title + '</span>')
            html_parts.append('<p><strong>Message:</strong> ' + message + '</p>')
            html_parts.append('<p><strong>Location:</strong> Line ' + str(line) + '</p>')
            
            if finding.get('code'):
                html_parts.append('<div class="code">' + finding.get('code', '') + '</div>')
            
            if finding.get('confidence'):
                confidence_pct = int(finding.get('confidence', 0.5) * 100)
                html_parts.append('<p><strong>ML Confidence:</strong> ' + str(confidence_pct) + '%</p>')
            
            html_parts.append('</div>')
    else:
        html_parts.append('<p>No issues found in the code analysis.</p>')
    
    html_parts.append('</body>')
    html_parts.append('</html>')
    
    html_content = '\n'.join(html_parts)
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html', encoding='utf-8')
    temp_file.write(html_content)
    temp_file.close()
    
    try:
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename + "_report_" + datetime.now().strftime('%Y%m%d_%H%M%S') + ".html",
            mimetype='text/html'
        )
    finally:
        # Clean up the temporary file after sending
        try:
            os.unlink(temp_file.name)
        except:
            pass

def download_csv_report(findings, summary, filename):
    """Generate and download CSV report."""
    import csv
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='', encoding='utf-8')
    writer = csv.writer(temp_file)
    
    # Write header
    writer.writerow(['Finding #', 'Type', 'Severity', 'Message', 'Line', 'Column', 'ML Confidence', 'Code'])
    
    # Write findings
    for i, finding in enumerate(findings, 1):
        writer.writerow([
            i,
            finding.get('type', 'Unknown'),
            finding.get('severity', 'Unknown'),
            finding.get('message', 'No description'),
            finding.get('line', ''),
            finding.get('column', ''),
            "{:.0f}%".format(finding.get('confidence', 0.5) * 100) if finding.get('confidence') else '',
            finding.get('code', '').replace('\n', ' ').replace('\r', ' ')
        ])
    
    temp_file.close()
    
    try:
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"{filename}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mimetype='text/csv'
        )
    finally:
        # Clean up the temporary file after sending
        try:
            os.unlink(temp_file.name)
        except:
            pass

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for code analysis."""
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({'error': 'No code provided'}), 400
    
    filename = data.get('filename', 'uploaded_code.py')
    code = data['code']
    
    # Analyze the code
    findings = analyzer.analyze(filename, code)
    adjusted_findings = add_simple_feedback_to_findings(findings, feedback_system)
    
    return jsonify({
        'filename': filename,
        'findings': adjusted_findings,
        'summary': {
            'total_findings': len(findings),
            'adjusted_findings': len(adjusted_findings),
            'analyzed_at': datetime.now().isoformat()
        }
    })

if __name__ == '__main__':
    # Initialize components
    init_components()
    
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Create static directory if it doesn't exist  
    if not os.path.exists('static'):
        os.makedirs('static')
    
    print("🚀 Smart Code Reviewer Web UI starting...")
    print("📝 Upload code files for intelligent analysis")
    print("🧠 ML feedback learning enabled")
    print("🌐 Open http://localhost:5000 in your browser")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
