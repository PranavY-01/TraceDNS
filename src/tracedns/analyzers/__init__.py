"""SPF, DMARC, and DKIM analyzers. Each returns findings and never prints."""

from tracedns.analyzers.dkim import analyze_dkim
from tracedns.analyzers.dmarc import analyze_dmarc
from tracedns.analyzers.spf import analyze_spf

__all__ = ["analyze_dkim", "analyze_dmarc", "analyze_spf"]
