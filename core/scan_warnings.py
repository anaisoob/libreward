"""Structured explanations for incomplete scans; no warnings are discarded."""
from collections import Counter


EXPLANATIONS = {
    'limits': ('Scan limits', 'The file was too large or its contents exceeded a scan limit. '
               'Try Check larger files in Settings. Very large files may still exceed ClamAV limits.'),
    'changed': ('Files changed or disappeared', 'Another application removed or replaced these files during scanning. '
                'This is common with browser caches. Close the application and scan again if needed.'),
    'access': ('Files could not be opened', 'The files were locked or access was denied. '
               'Close applications using them and scan again. Their contents have not been fully checked.'),
    'encrypted': ('Encrypted contents', 'ClamAV could not inspect encrypted contents without decryption. '
                  'An encrypted-file alert alone does not establish that the file contains malware.'),
    'other': ('Other incomplete checks', 'Review the file details below for the reason.'),
}


def alert_warning(status):
    if status.startswith('Heuristics.Limits.Exceeded'):
        return 'limits'
    if status.startswith('Heuristics.Encrypted.'):
        return 'encrypted'
    return None


def warning_category(reason):
    text = str(reason).lower()
    if 'limit' in text:
        return 'limits'
    if 'encrypted' in text:
        return 'encrypted'
    if any(value in text for value in ('no such file', 'not found', 'cannot find', 'changed', 'disappeared')):
        return 'changed'
    if any(value in text for value in ('permission', 'access denied', 'locked', "can't open", 'lstat() failed')):
        return 'access'
    return 'other'


def clean_reason(reason):
    reason = str(reason).strip()
    for suffix in (' FOUND', ' ERROR', ' WARNING'):
        if reason.endswith(suffix):
            reason = reason[:-len(suffix)].rstrip()
    return reason


class WarningSummary:
    def __init__(self):
        self.counts = Counter()
        self.details = []

    def add(self, path, reason, category=None):
        category = category or warning_category(reason)
        self.counts[category] += 1
        if len(self.details) < 200:
            self.details.append({'path': str(path), 'reason': clean_reason(reason), 'category': category})
        return category


def warning_report(result):
    counts = result.get('warning_counts', {})
    lines = []
    if counts:
        lines.append('WHY SOME FILES WERE NOT FULLY CHECKED\n')
        for category, (title, explanation) in EXPLANATIONS.items():
            if counts.get(category):
                if category == 'limits' and result.get('uses_system_daemon'):
                    explanation = ('The existing antivirus service controls these limits. '
                                   'For LibreWard large-file limits, enable Check larger files and turn off parallel scanning. '
                                   'Some large or complex files will still exceed engine limits.')
                elif category == 'limits' and result.get('scan_profile') == 'extended':
                    explanation = ('Larger-file checking was enabled, but the file or its contents still exceeded '
                                   'an engine limit. Where applicable, extract the contents and scan them separately. '
                                   'ClamAV has a technical file-size limit of about 2 GB.')
                lines.append(f'{title}: {counts[category]}\n{explanation}\n\n')
        lines.append('These are incomplete checks, not confirmed infections. Detections are listed separately.\n\n')
        for detail in result.get('warning_details', []):
            lines.append(f"{detail['path']}: {detail['reason']}\n")
        count = sum(counts.values())
        shown = len(result.get('warning_details', []))
        if count > shown:
            lines.append(f'\nShowing {shown} of {count} warning details. Counts include all warnings.\n')
    if result.get('infected'):
        lines.append('\nDETECTIONS TO REVIEW\n')
        for path, status in result['infected']:
            lines.append(f'{path}: {status}\n')
        lines.append('\nHeuristic alerts flag suspicious structure or behavior and require review. '
                     'EICAR is an antivirus test signature. Review detections before deleting files.\n')
    return ''.join(lines)
