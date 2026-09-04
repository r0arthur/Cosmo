"""Trend + findings store and compliance mapping.

A side layer over the pure engine: a trigger adapter records each scan's
findings here so cosmo can report lifecycle (introduced/fixed over time), feed
the noisiest-rules signal back into the skills loop, hold the coordinated-
disclosure queue, and roll findings up to OWASP Top 10 for compliance.
"""
from .compliance import ComplianceRow, map_report, owasp_for, owasp_name
from .trends import ScanSummary, TrendStore

__all__ = [
    "TrendStore", "ScanSummary",
    "map_report", "owasp_for", "owasp_name", "ComplianceRow",
]
