"""Plain-language domain protection UI; system work belongs to backends."""
import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QListWidget, QMessageBox,
    QScrollArea, QVBoxLayout, QWidget,
)
from backends import backend
from core.authorization import AuthorizationError
from config import save_config
from core.dns_providers import PROVIDERS
from core.internet import CATEGORIES, DiskDomainLists as DomainLists, internet_available, normalize_domain, preferences


class InternetProtectionPage:
    def __init__(self, window):
        self.window = window
        self.state = None
        self.pending = False
        self.recovery_noticed = False
        # Cancelling stops before the system change starts or while authorization is pending.
        self.cancel_lock = threading.Lock()
        self.cancel_requested = False
        self.backend_started = False
        self.store = DomainLists(backend.data_dir())
        self.page, outer = window.page('Internet protection', 'Block connections to unwanted website domains.')
        self.page.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.health_timer = QTimer(self.page)
        self.health_timer.setInterval(30000)
        self.health_timer.timeout.connect(self.check_health)
        self.health_timer.start()
        # Protection follows the open app: while it is on, tell the local filter
        # LibreWard is still running. On the next start, offer to restore it.
        self.keepalive_timer = QTimer(self.page)
        self.keepalive_timer.setInterval(20000)
        self.keepalive_timer.timeout.connect(self.keepalive)
        self.keepalive_timer.start()
        self.keepalive()
        self.startup_pending = self.protection_remembered()
        scroll = QScrollArea()
        self.scroll = scroll
        self.scroll_position = None
        self.scroll_restore_timer = QTimer(self.page)
        self.scroll_restore_timer.setSingleShot(True)
        self.scroll_restore_timer.timeout.connect(self.restore_scroll)
        scroll.setWidgetResizable(True)
        content = QWidget()
        content.setObjectName('settingsContent')
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        card, box = window.card()
        self.status = window.label('Checking Internet protection…', 'statusValue')
        box.addWidget(self.status)
        self.info = window.label('', 'muted')
        self.info.setWordWrap(True)
        box.addWidget(self.info)
        row = QHBoxLayout()
        # One switch; the state is checked automatically while this page is open.
        self.toggle_button = window.button('Turn on', self.toggle, variant='primary')
        self.toggle_button.setEnabled(False)
        row.addWidget(self.toggle_button)
        row.addStretch()
        box.addLayout(row)
        # Shown only while protection is on and saved choices differ from the active ones.
        self.pending_bar = QWidget()
        pending = QHBoxLayout(self.pending_bar)
        pending.setContentsMargins(0, 6, 0, 0)
        pending_text = window.label('Your changes are saved but not active yet.', 'sectionTitle')
        pending_text.setWordWrap(True)
        pending.addWidget(pending_text, 1)
        self.apply_button = window.button('Apply changes', lambda: self.apply(changes=True), variant='primary')
        pending.addWidget(self.apply_button)
        self.pending_bar.hide()
        box.addWidget(self.pending_bar)
        self.notice = window.label('', 'muted')
        self.notice.setWordWrap(True)
        box.addWidget(self.notice)
        layout.addWidget(card)
        try:
            saved = preferences(window.config)
        except (ValueError, TypeError):
            saved = {'categories': ['dangerous'], 'provider': 'adguard', 'allowed': [], 'blocked': []}
            self.notice.setText('Saved website settings could not be read. Review them before applying protection.')
        # Behind systemd-resolved, allowed lookups go to a chosen DNS service over TLS.
        self.public_card, box = window.card()
        box.addWidget(window.label('ENCRYPTED DNS SERVICE', 'eyebrow'))
        self.provider = QComboBox()
        for key, provider in PROVIDERS.items():
            self.provider.addItem(provider.name + (' (recommended)' if key == 'adguard' else ''), key)
        self.provider.setCurrentIndex(max(0, self.provider.findData(saved['provider'])))
        self.provider.currentIndexChanged.connect(self.provider_changed)
        box.addWidget(self.provider)
        self.provider_info = window.label('', 'muted')
        self.provider_info.setWordWrap(True)
        box.addWidget(self.provider_info)
        note = window.label('LibreWard first checks every website name on this computer against your choices below. '
                            'Allowed lookups then go to this service, encrypted where the network allows it. '
                            'It may block more on its own. Local network and VPN names are not sent to it.', 'muted')
        note.setWordWrap(True)
        box.addWidget(note)
        layout.addWidget(self.public_card)
        self.public_card.hide()
        self.provider_changed(notify=False)
        card, box = window.card()
        box.addWidget(window.label('WHAT TO BLOCK', 'eyebrow'))
        self.categories = {}
        for key, (title, _) in CATEGORIES.items():
            checkbox = QCheckBox(title + (' (recommended)' if key == 'dangerous' else ' (optional)'))
            checkbox.setChecked(key in saved['categories'])
            checkbox.toggled.connect(self.changed)
            self.categories[key] = checkbox
            box.addWidget(checkbox)
        note = window.label('Ads and tracking lists can stop parts of a website from working. '
                            'Add its exact domain to Allowed websites if needed.', 'muted')
        note.setWordWrap(True)
        box.addWidget(note)
        box.addWidget(window.button('Update lists now', self.download))
        layout.addWidget(card)
        lists_row = QHBoxLayout()
        self.domain_lists = {}
        self.domain_fields = []
        for key, title in (('allowed', 'Allowed websites'), ('blocked', 'Blocked websites')):
            card, box = window.card()
            box.addWidget(window.label(title, 'sectionTitle'))
            note = window.label('Allow overrides LibreWard blocklists.' if key == 'allowed' else
                                'Always block these domains unless allowed.', 'muted')
            note.setWordWrap(True)
            box.addWidget(note)
            listing = QListWidget()
            listing.addItems(saved[key])
            listing.setMaximumHeight(150)
            self.domain_lists[key] = listing
            box.addWidget(listing)
            field = QLineEdit()
            self.domain_fields.append(field)
            field.setPlaceholderText('example.org (exact domain)')
            box.addWidget(field)
            add = window.button('Add website', lambda checked=False, k=key, f=field: self.add_domain(k, f))
            box.addWidget(add)
            field.returnPressed.connect(lambda k=key, f=field: self.add_domain(k, f))
            box.addWidget(window.button('Remove selected', lambda checked=False, k=key: self.remove_domain(k)))
            lists_row.addWidget(card)
        layout.addLayout(lists_row)
        note = window.label('This protection blocks exact domain names, not page contents. '
                            'Subdomains need their own entries. It cannot remove every ad. '
                            'Apps using their own DNS and already-open connections may bypass it. '
                            'No browsing history or blocked-request history is recorded. '
                            'Allowed websites only removes LibreWard blocks; it cannot override other security tools.', 'muted')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.advanced_toggle = QCheckBox('Show how protection works')
        layout.addWidget(self.advanced_toggle)
        self.advanced = window.label('Linux: a local service checks an indexed database on disk. With NetworkManager, '
                                    'NetworkManager forwards allowed requests, including VPN domains. With systemd-resolved, '
                                    'allowed requests go to the selected DNS service over TLS, while resolved keeps sending '
                                    'VPN and local network names to their own servers. VPN connection settings are unchanged. '
                                    'Protection works while LibreWard is open. If the computer restarts with protection on, '
                                    'LibreWard starts with it in the tray and protection continues. Closing the window keeps LibreWard running in the tray; quitting LibreWard or pausing '
                                    'removes LibreWard’s blocks until you enable protection again.\n\n'
                                    'Sources: The Block List Project, downloaded over HTTPS from GitHub. '
                                    'Upstream source URLs and license headers are preserved in the local list cache. '
                                    'Lists can contain mistakes and are refreshed only when you choose to update. '
                                    'Downloading lists contacts GitHub; your website exceptions are not uploaded.', 'muted')
        self.advanced.setWordWrap(True)
        self.advanced.hide()
        layout.addWidget(self.advanced)
        # Technical status from the backend, for those who open "how it works".
        self.method_info = window.label('', 'muted')
        self.method_info.setWordWrap(True)
        self.method_info.hide()
        layout.addWidget(self.method_info)
        self.advanced_toggle.toggled.connect(self.advanced.setVisible)
        self.advanced_toggle.toggled.connect(self.method_info.setVisible)
        layout.addStretch()

    def protection_remembered(self):
        return self.window.config.get('internet_protection_on') is True

    def keepalive(self):
        if self.protection_remembered():
            backend.internet_protection_keepalive()

    def remember_protection(self, enabled):
        """Remember whether protection is on and start LibreWard at login accordingly."""
        try:
            backend.set_autostart(enabled)
            if self.protection_remembered() != enabled:
                config = dict(self.window.config, internet_protection_on=enabled)
                save_config(config)
                self.window.config = config
        except (OSError, ValueError, NotImplementedError) as exc:
            self.window.log.appendPlainText(f'Cannot update starting LibreWard with the computer: {exc}')
        self.keepalive()

    def startup_state(self, state):
        self.show_state(state)
        if state.get('active') or not state.get('supported'):
            return
        self.window.showNormal()
        self.window.raise_()
        self.window.switch_page('internet')
        if QMessageBox.question(self.window, 'Internet protection',
                'Internet protection was on when LibreWard was last running, but it is off now. Turn it on again?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes) == QMessageBox.StandardButton.Yes:
            self.apply(confirmed=True)
        else:
            self.remember_protection(False)

    def public_mode(self):
        """Behind systemd-resolved the filter forwards to a selected public DNS service."""
        return bool(self.state and self.state.get('mode') == 'resolved')

    def provider_changed(self, *_args, notify=True):
        provider = PROVIDERS[self.provider.currentData()]
        self.provider_info.setText(f'{provider.blocks}\nProvided by a third party under its own terms: {provider.homepage}')
        if notify:
            self.changed()

    def changed(self):
        """Save every edit at once, so status checks and restarts never lose it."""
        try:
            self.persist(self.settings())
        except OSError as exc:
            self.notice.setText(f'Your change could not be saved: {exc}')
        self.update_pending()

    def lists_version(self):
        try:
            return self.store.load().get('updated')
        except Exception:
            return None

    def active_choices(self, settings=None):
        """What the running filter depends on; the DNS service only behind resolved."""
        settings = dict(settings or self.settings())
        if not self.public_mode():
            settings.pop('provider', None)
        settings['lists'] = self.lists_version()
        return settings

    def has_pending(self):
        applied = self.window.config.get('internet_protection_applied')
        return bool(self.state and self.state.get('active') and applied is not None
                    and self.active_choices() != applied)

    def remember_applied(self):
        config = dict(self.window.config, internet_protection_applied=self.active_choices())
        try:
            save_config(config)
        except OSError:
            pass
        self.window.config = config

    def update_pending(self):
        self.pending_bar.setVisible(self.has_pending())

    def settings(self):
        return {'categories': [key for key, check in self.categories.items() if check.isChecked()],
                'provider': self.provider.currentData(),
                **{key: [listing.item(i).text() for i in range(listing.count())]
                   for key, listing in self.domain_lists.items()}}

    def persist(self, settings):
        config = dict(self.window.config)
        config['internet_protection'] = settings
        save_config(config)
        self.window.config = config

    def add_domain(self, key, field):
        if self.window.operation:
            return
        try:
            domain = normalize_domain(field.text())
        except ValueError as exc:
            QMessageBox.warning(self.window, 'Website domain', str(exc))
            return
        listing = self.domain_lists[key]
        if not listing.findItems(domain, Qt.MatchFlag.MatchExactly):
            listing.addItem(domain)
            listing.sortItems()
        # Moving a domain between lists resolves the contradiction immediately.
        other = self.domain_lists['blocked' if key == 'allowed' else 'allowed']
        for item in other.findItems(domain, Qt.MatchFlag.MatchExactly):
            other.takeItem(other.row(item))
        field.clear()
        self.changed()

    def remove_domain(self, key):
        if self.window.operation:
            return
        listing = self.domain_lists[key]
        for item in listing.selectedItems():
            listing.takeItem(listing.row(item))
        self.changed()

    def request_refresh(self):
        self.pending = True
        self.maybe_refresh()

    def maybe_refresh(self):
        if self.startup_pending and self.window.operation is None and QApplication.activeModalWidget() is None:
            if self.window.start_task('internet-status', backend.inspect_internet_protection, on_done=self.startup_state):
                self.startup_pending = False
                self.status.setText('Checking domain protection…')
            return
        if (self.pending and self.window.operation is None
                and QApplication.activeModalWidget() is None
                and self.window.pages.currentIndex() == self.window.page_indices['internet']):
            self.refresh()

    def refresh(self):
        if self.window.start_task('internet-status', backend.inspect_internet_protection, on_done=self.show_state):
            self.pending = False
            self.status.setText('Checking domain protection…')

    def check_health(self):
        if self.state and self.state.get('active') and self.window.pages.currentIndex() == self.window.page_indices['internet']:
            self.request_refresh()

    def prepare_operation(self):
        if self.window.pages.currentIndex() == self.window.page_indices['internet']:
            self.scroll_position = self.scroll.verticalScrollBar().value()
            # Disabling the focused status button otherwise transfers focus to
            # widgets lower down, and QScrollArea scrolls those into view.
            self.page.setFocus(Qt.FocusReason.OtherFocusReason)

    def restore_scroll(self):
        if self.scroll_position is not None:
            self.scroll.verticalScrollBar().setValue(self.scroll_position)
            self.scroll_position = None

    def show_state(self, state):
        self.state = state
        # Say once that the filter stopped; later status checks keep other notices.
        if state.get('recovered') and not state.get('active') and not self.recovery_noticed:
            self.recovery_noticed = True
            self.notice.setText('The filter stopped. Normal internet access was restored automatically. You can enable protection again.')
        elif state.get('active'):
            self.recovery_noticed = False
        active = state.get('active', False)
        supported = state.get('supported', False)
        public = self.public_mode()
        self.public_card.setVisible(public)
        # The page shows the saved choices; the active ones are compared, never copied back.
        if active and self.window.config.get('internet_protection_applied') is None:
            self.remember_applied()  # protection enabled by an earlier version
        self.status.setText('Internet protection is on' if active and supported else
                            'Internet protection needs attention' if active else
                            'Internet protection is off' if supported else 'Not available on this computer')
        self.status.setProperty('severity', 'success' if active and supported else 'warning')
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        provider = PROVIDERS.get(state.get('provider'))
        if active and supported:
            count = state.get('count', 0)
            text = f"Blocking {count:,} website{'s' if count != 1 else ''}."
            if provider is not None:
                text += f' Other lookups go to {provider.name}.'
        elif active:
            text = 'Turn protection off to restore normal internet access, then turn it on again.'
        elif supported:
            text = 'Turn on to block dangerous websites on this computer.'
        else:
            text = state.get('message', '')
        self.info.setText(text)
        self.method_info.setText(state.get('message', '') if supported else '')
        self.toggle_button.setText('Turn off' if active else 'Turn on')
        self.toggle_button.setObjectName('secondaryButton' if active else 'primaryButton')
        self.toggle_button.style().unpolish(self.toggle_button)
        self.toggle_button.style().polish(self.toggle_button)
        self.update_controls()

    def update_controls(self):
        idle = self.window.operation is None
        # A background status check must not interrupt editing.
        editable = idle or self.window.operation == 'internet-status'
        self.toggle_button.setEnabled(idle and bool(self.state and (self.state.get('supported') or self.state.get('active'))))
        self.apply_button.setEnabled(idle)
        for widget in [*self.categories.values(), *self.domain_lists.values(), *self.domain_fields, self.provider]:
            widget.setEnabled(editable)
        self.update_pending()
        if idle and self.scroll_position is not None:
            self.scroll_restore_timer.start(0)

    def unknown(self):
        self.state = None
        self.status.setText('Protection status needs checking')
        self.status.setProperty('severity', 'warning')
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.notice.setText('The last change was not confirmed. LibreWard checks the status again when this page is open.')
        self.pending = True
        self.update_controls()

    def download(self):
        if self.window.operation:
            return
        settings = self.settings()
        if not settings['categories']:
            QMessageBox.information(self.window, 'Protection lists', 'Choose at least one protection category to download.')
            return
        if not self.window.confirm('Update lists',
                'Download the latest lists of unwanted websites from The Block List Project on GitHub?'):
            return
        def work():
            bundle = self.store.update(settings['categories'], self.window.events.put)
            self.window.events.put(f"Downloaded {bundle.get('count', 0):,} websites.\n")
            return {'updated': bundle['updated']}

        def done(_bundle):
            self.notice.setText('Lists updated.')
            self.update_pending()
        self.window.start_task('internet-download', work, title='Update lists', on_done=done)

    def toggle(self):
        if self.state and self.state.get('active'):
            self.pause()
        else:
            self.apply()

    def consent_text(self, settings, changes):
        """Short; a new third-party DNS service always gets its own explanation."""
        applied = self.window.config.get('internet_protection_applied') or {}
        parts = []
        if self.public_mode() and (not changes or applied.get('provider') != settings['provider']):
            provider = PROVIDERS[settings['provider']]
            parts.append(f'Website lookups that LibreWard allows go to {provider.name}, a third-party service that is '
                         f'not part of LibreWard, with its own terms and privacy policy ({provider.homepage}). '
                         f'{provider.blocks} It can see which websites '
                         'this computer visits after LibreWard’s checks. Both are provided with no warranty, to the '
                         'extent permitted by law.')
        if self.state.get('needs_dns_install'):
            parts.append(f"LibreWard will install the {self.state.get('dns_package') or 'dnsmasq'} package from your "
                         'system’s software sources.')
        if changes:
            return '\n\n'.join(parts)
        return '\n\n'.join(parts + [
            'Some websites or apps may stop working; you can allow them later. Protection works while LibreWard '
            'is running, also from the tray. Quitting LibreWard turns protection off. Your password is needed.'])

    def apply(self, confirmed=False, changes=False):
        if self.window.operation or not self.state or not self.state.get('supported'):
            return
        settings = self.settings()
        if not settings['categories'] and not settings['blocked']:
            QMessageBox.information(self.window, 'Internet protection', 'Choose what to block first.')
            return
        text = self.consent_text(settings, changes)
        if not confirmed and text and not self.window.confirm(
                'Apply changes' if changes else 'Turn on Internet protection', text):
            return
        self.window.privileged_terminal_commands = ''
        if not self.window.ensure_system_authorization():
            return
        try:
            self.persist(settings)
        except OSError as exc:
            QMessageBox.warning(self.window, 'Settings', str(exc))
            return
        def work():
            if not internet_available():
                raise ValueError('This computer is not connected to the internet. Connect, then try again. '
                                 'No settings were changed.')
            available = set(self.store.load()['lists'])
            if any(key not in available for key in settings['categories']):
                self.store.update(settings['categories'], self.window.events.put)
            self.window.events.put('Preparing the domain database on disk…\n')
            with self.store.prepare(settings) as domains:
                if not len(domains):
                    raise ValueError('No domains remain to block after your allowed websites were applied.')
                self.window.events.put(f'Applying {len(domains):,} blocked domains. Waiting for system authorization…\n')
                self.start_system_change()
                state = backend.apply_internet_protection(
                    domains, provider=settings['provider'] if self.public_mode() else None)
            self.window.events.put(f"Applied {state['count']:,} exact-domain blocks with the local filter.\n")
            return state
        self.reset_cancel()
        if self.window.start_task('internet-apply', work,
                                  title='Applying changes' if changes else 'Turning on Internet protection',
                                  on_done=self.applied):
            self.offer_cancel()

    def reset_cancel(self):
        # Before the worker starts, so its checkpoint never sees a stale request.
        with self.cancel_lock:
            self.cancel_requested = self.backend_started = False
        backend.reset_cancellation()

    def start_system_change(self):
        """Worker checkpoint: honour a cancel request made before the system change."""
        with self.cancel_lock:
            if self.cancel_requested:
                raise AuthorizationError('cancelled', 'Cancelled. No changes were made.')
            self.backend_started = True

    def offer_cancel(self):
        dialog = self.window.update_dialog
        if dialog is None:
            return

        def cancel():
            with self.cancel_lock:
                before_change = not self.backend_started
                self.cancel_requested = before_change
            if before_change or backend.cancel_authorization():
                dialog.status.setText('Cancelling…')
            else:
                dialog.status.setText('Authorization was already given. LibreWard is finishing the change safely '
                                      'and cannot stop it now.')
            dialog.cancel_button.setEnabled(False)
        dialog.enable_cancel(cancel)

    def applied(self, state):
        self.show_state(state)
        if state.get('active'):
            self.remember_applied()
        self.remember_protection(bool(state.get('active')))
        self.notice.setText('If a website still opens, restart the browser.' if state.get('active') else '')
        self.update_pending()

    def pause(self):
        if self.window.operation or not self.state or not self.state.get('active'):
            return
        if not self.window.confirm('Turn off Internet protection',
                'Websites will no longer be blocked. Your choices are kept for next time. Your password is needed.'):
            return
        self.window.privileged_terminal_commands = ''
        if not self.window.ensure_system_authorization():
            return
        def work():
            self.start_system_change()
            return backend.apply_internet_protection([])
        self.reset_cancel()
        if self.window.start_task('internet-pause', work, title='Turning off Internet protection', on_done=self.paused):
            self.offer_cancel()

    def paused(self, state):
        self.show_state(state)
        if not state.get('active'):
            self.remember_protection(False)
        self.notice.setText('')
