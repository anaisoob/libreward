# Release License Files

This directory is for license files included in packaged LibreWard releases.

Before publishing a release archive:

- Add the LibreWard GPL license text.
- Include third-party Python dependency license notices where required. The
  current GUI dependency is CustomTkinter, which is distributed under CC0, and
  its dark mode helper `darkdetect` is BSD-3-Clause.
- If bundling ClamAV, include the ClamAV license and copyright notices from the
  official ClamAV distribution.
- Do not remove or rewrite upstream ClamAV notices.
- Make the About window and release archive clear that LibreWard executes
  ClamAV command-line tools and does not present ClamAV as original LibreWard
  code.
