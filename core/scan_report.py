"""Plain-language presentation shared by scan reports."""
from core.scan_warnings import EXPLANATIONS


def format_duration(seconds):
    seconds = max(0, int(seconds or 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{hours:02d}:{minutes:02d}:{seconds:02d}'


def friendly_report(result):
    if result.get('infected'):
        heading = 'Potential threats found. Review the detected files before taking action.'
    elif result.get('errors') or result.get('stopped'):
        heading = 'The scan did not finish completely. Some files may not have been checked.'
    elif result.get('warnings'):
        heading = 'No threats detected in the checked contents. Some files could not be fully checked.'
    else:
        heading = 'No threats detected.'
    lines = [heading, '', f"Files processed: {result.get('scanned', 0):,}",
             f"Files requiring review: {len(result.get('infected', []))}",
             f"Scan duration: {format_duration(result.get('duration_seconds'))}"]
    if result.get('duration_seconds') is None:
        lines[-1] = 'Scan duration: unavailable'
    counts = result.get('warning_counts', {})
    if result.get('warnings') and not counts:
        lines.extend(['', 'Some files could not be fully checked. See technical details for the reasons.'])
    if result.get('infected'):
        lines.extend(['', 'Detected files to review'])
        lines.extend(path for path, _ in result['infected'])
    if result.get('errors'):
        lines.extend(['', 'A scanning problem occurred. See technical details before relying on this result.'])
    if counts:
        lines.extend(['', 'Files that could not be fully checked'])
        for category, count in counts.items():
            title, explanation = EXPLANATIONS.get(category, EXPLANATIONS['other'])
            if category == 'limits':
                title = 'Files too large or too complex to fully check'
                explanation = ('Try “Check larger files” in Settings. Some very large files may still '
                               'be beyond the antivirus engine’s limits.')
                if result.get('uses_system_daemon'):
                    explanation = ('The system antivirus service controls this limit. To use LibreWard’s '
                                   'larger-file setting, enable “Check larger files” and turn off parallel scanning.')
                elif result.get('scan_profile') == 'extended':
                    explanation = ('Larger-file checking was already enabled. If possible, extract the '
                                   'archive into a folder and scan that folder. Very large files may still exceed engine limits.')
            lines.extend([f'{title}: {count}', explanation, ''])
        lines.append('This does not mean these files are infected. Their contents could not be fully checked.')
        for detail in result.get('warning_details', []):
            lines.append(detail['path'])
        shown = len(result.get('warning_details', []))
        if sum(counts.values()) > shown:
            lines.append(f'Showing {shown} file paths; the counts above include all incomplete checks.')
    return '\n'.join(lines)
