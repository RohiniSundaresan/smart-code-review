#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Simple Feedback Learning - Minimal but Useful Implementation
Just the essentials for learning from user feedback to reduce false positives
"""

import json
import os
from datetime import datetime


class SimpleFeedback:
    """Minimal feedback system for learning from user responses."""
    
    def __init__(self, feedback_file="feedback.json"):
        self.feedback_file = feedback_file
        self.rule_weights = self.load_weights()
    
    def load_weights(self):
        """Load simple rule weights from file."""
        try:
            if os.path.exists(self.feedback_file):
                with open(self.feedback_file, 'r') as f:
                    data = json.load(f)
                return data.get('weights', {})
        except Exception:
            pass
        
        # Default weights - security high, style lower
        return {
            'security': 0.9,
            'style': 0.5,
            'static': 0.7
        }
    
    def save_weights(self):
        """Save rule weights to file."""
        try:
            data = {
                'weights': self.rule_weights, 
                'updated': datetime.now().isoformat(),
                'total_feedback': getattr(self, 'feedback_count', 0)
            }
            with open(self.feedback_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def record_feedback(self, finding_type, useful=True):
        """Record if a finding was useful or not.
        
        Args:
            finding_type (str): Type of finding ('security', 'style', 'static')
            useful (bool): Whether the finding was useful
        """
        current_weight = self.rule_weights.get(finding_type, 0.5)
        
        if useful:
            # Slightly increase weight (max 1.0)
            self.rule_weights[finding_type] = min(1.0, current_weight + 0.1)
        else:
            # Decrease weight more significantly for false positives (min 0.1)
            self.rule_weights[finding_type] = max(0.1, current_weight - 0.15)
        
        # Track feedback count
        if not hasattr(self, 'feedback_count'):
            self.feedback_count = 0
        self.feedback_count += 1
        
        self.save_weights()
        print(f"Feedback recorded: {finding_type} -> {'useful' if useful else 'not useful'} (weight: {self.rule_weights[finding_type]:.2f})")
    
    def should_show_finding(self, finding_type, confidence_threshold=0.3):
        """Check if finding should be shown based on learned weights.
        
        Args:
            finding_type (str): Type of finding
            confidence_threshold (float): Minimum weight to show finding
            
        Returns:
            bool: Whether to show the finding
        """
        weight = self.rule_weights.get(finding_type, 0.5)
        return weight > confidence_threshold
    
    def get_adjusted_severity(self, finding_type, original_severity):
        """Adjust severity based on learned weights.
        
        Args:
            finding_type (str): Type of finding
            original_severity (str): Original severity level
            
        Returns:
            str: Adjusted severity level
        """
        weight = self.rule_weights.get(finding_type, 0.5)
        
        # Don't adjust security findings - they're always important
        if finding_type == 'security':
            return original_severity
        
        if weight < 0.3:
            # Low confidence - reduce severity
            if original_severity == 'high':
                return 'medium'
            elif original_severity == 'medium':
                return 'low'
        elif weight > 0.8:
            # High confidence - increase severity for non-security
            if original_severity == 'low' and finding_type == 'static':
                return 'medium'
        
        return original_severity
    
    def get_stats(self):
        """Get simple statistics about the feedback model."""
        return {
            'total_feedback': getattr(self, 'feedback_count', 0),
            'rule_weights': self.rule_weights.copy(),
            'most_trusted': max(self.rule_weights.items(), key=lambda x: x[1]) if self.rule_weights else None,
            'least_trusted': min(self.rule_weights.items(), key=lambda x: x[1]) if self.rule_weights else None
        }


def add_simple_feedback_to_findings(findings, feedback_system):
    """Filter and adjust findings based on simple feedback learning.
    
    Args:
        findings (list): List of findings from analyzer
        feedback_system (SimpleFeedback): Feedback system instance
        
    Returns:
        list: Filtered and adjusted findings
    """
    adjusted_findings = []
    
    for finding in findings:
        finding_type = finding.get('type', 'unknown')
        
        # Skip findings that have been learned to be unhelpful
        if not feedback_system.should_show_finding(finding_type):
            continue
        
        # Adjust severity based on learning
        original_severity = finding.get('severity', 'medium')
        adjusted_severity = feedback_system.get_adjusted_severity(finding_type, original_severity)
        
        # Create adjusted finding
        adjusted_finding = finding.copy()
        adjusted_finding['severity'] = adjusted_severity
        adjusted_finding['confidence'] = feedback_system.rule_weights.get(finding_type, 0.5)
        
        adjusted_findings.append(adjusted_finding)
    
    return adjusted_findings
