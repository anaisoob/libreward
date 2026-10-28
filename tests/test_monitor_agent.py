"""Background folder monitoring agent: settings, scans, notifications and state."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backends.base import RuntimeInfo
from core import monitor_agent
from core.monitor_agent import MonitorAgent, monitor_settings, read_state
from core.runtime import StartupStatus


class MonitorAgentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.watched = self.root / 'Downloads'
        self.watched.mkdir()
        self.config_file = self.root / 'config/config.json'
        self.config_file.parent.mkdir()
        self.patchers = [
            patch.object(monitor_agent.backend, 'data_dir', return_value=self.root / 'data'),
            patch.object(monitor_agent.backend, 'config_dir', return_value=self.root / 'config'),
            patch.object(monitor_agent.backend, 'log_dir', return_value=self.root / 'data/logs'),
            patch.object(monitor_agent, 'CONFIG_FILE', self.config_file),
            patch.object(monitor_agent, 'load_config', side_effect=self.load_config),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.ready = StartupStatus(RuntimeInfo('system-path', 'clamscan', 'freshclam', 'ClamAV 1.5.2', '1.5.2'),
                                   True, True, False, True)
        self.notify = Mock(return_value=True)
        self.open_application = Mock()
        self.logged = []

    def tearDown(self):
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.directory.cleanup()

    def load_config(self):
        try:
            return json.loads(self.config_file.read_text())
        except (OSError, ValueError):
            return None

    def save(self, **config):
        self.config_file.write_text(json.dumps(config))

    def agent(self, gui_running=False):
        self.close_notification = Mock(return_value=True)
        return MonitorAgent(notify=self.notify, close_notification=self.close_notification,
                            open_application=self.open_application,
                            gui_running=lambda: gui_running, log=self.logged.append)

    def scanning_agent(self, result):
        agent = self.agent()
        agent.config = {'watch_folders_enabled': True, 'watched_folders': [str(self.watched)]}
        agent.settings = monitor_settings(agent.config)
        agent.status = self.ready
        agent.monitor = Mock()
        agent.monitor.came_from.return_value = None  # not a browser download

        def run(service, *_args, **_kwargs):
            service.result = result

        return agent, patch('core.monitor_agent.ScanService.run', autospec=True, side_effect=run)

    def test_settings_follow_switch_and_exclude_own_folders(self):
        self.assertIsNone(monitor_settings({'watched_folders': [str(self.watched)]}))
        self.assertIsNone(monitor_settings({'watch_folders_enabled': True, 'watched_folders': [],
                                            'follow_download_folders': False}))
        roots, patterns = monitor_settings({'watch_folders_enabled': True, 'watched_folders': [str(self.watched), 3]})
        self.assertEqual(roots, [str(self.watched)])
        self.assertIn(str(self.root / 'data'), patterns)
        self.assertIn(str(self.root / 'config'), patterns)
        # Browser download folders join the chosen ones, unless following browsers is off.
        browser = str(self.root / 'Browser downloads')
        config = {'watch_folders_enabled': True, 'watched_folders': [str(self.watched)]}
        self.assertEqual(monitor_settings(config, [browser, str(self.watched)])[0], [str(self.watched), browser])
        self.assertEqual(monitor_settings(dict(config, follow_download_folders=False), [browser])[0],
                         [str(self.watched)])

    def test_download_folder_chosen_later_in_a_browser_is_protected(self):
        from core.download_folders import DownloadFolder
        agent = self.agent()
        agent.config = {'watch_folders_enabled': True, 'watched_folders': [str(self.watched)]}
        later = str(self.root / 'Chosen later')
        with patch('core.download_folders.settings_signature', return_value=(('prefs', 1),)), \
                patch('core.download_folders.discover_download_folders',
                      return_value=[DownloadFolder(str(self.watched), ('Firefox',))]) as discover:
            agent.follow_browsers(100)
            agent.follow_browsers(200)  # unchanged browser settings: not searched again
        self.assertEqual(discover.call_count, 1)
        with patch('core.download_folders.settings_signature', return_value=(('prefs', 2),)), \
                patch('core.download_folders.discover_download_folders',
                      return_value=[DownloadFolder(str(self.watched), ('Firefox',)), DownloadFolder(later, ('Chrome',))]):
            agent.follow_browsers(300)
        self.assertEqual(agent.discovered, [str(self.watched), later])
        self.assertIn(later, monitor_settings(agent.config, agent.discovered)[0])
        self.assertEqual(read_state()['discovered_folders'], [str(self.watched), later])
        self.assertIn('download folder(s) chosen in a browser', self.logged[-1])

    def test_clean_files_notify_quietly_with_names(self):
        agent, scan = self.scanning_agent({'infected': [], 'infected_found': False, 'errors': False,
                                               'warnings': False, 'stopped': False, 'scanned': 1})
        path = str(self.watched / 'clean.zip')
        with scan:
            agent.scan([path])
        _title, message = self.notify.call_args.args
        self.assertIn('No threats found', message)
        self.assertIn('clean.zip', message)
        # The result is always a new notification, so GNOME shows it.
        self.assertEqual(self.notify.call_args.kwargs, {'warning': False, 'replace': None})
        self.close_notification.assert_called_with(f'check:{path}')
        state = read_state()
        self.assertEqual(state['last_scan']['outcome'], 'No threats found')
        self.assertEqual(state.get('threats', []), [])

    def test_threats_are_recorded_and_notification_opens_libreward(self):
        path = str(self.watched / 'eicar.com')
        agent, scan = self.scanning_agent({'infected': [(path, 'Eicar-Signature FOUND')], 'infected_found': True,
                                               'errors': False, 'warnings': False, 'stopped': False, 'scanned': 1})
        with scan:
            agent.scan([path])
            agent.scan([path])  # the same file found again is listed once
        self.assertEqual(self.notify.call_args.args[0], '⚠ LibreWard — dangerous file found')
        self.assertIn('eicar.com', self.notify.call_args.args[1])
        self.assertTrue(self.notify.call_args.kwargs['warning'])
        self.assertIn('LibreWard asks what to do with it', self.notify.call_args.args[1])
        # Nobody had LibreWard open, so it opens to ask what to do.
        self.open_application.assert_called_with('--threats')
        threats = read_state()['threats']
        self.assertEqual([(entry['path'], entry['threat']) for entry in threats],
                         [(path, 'Eicar-Signature FOUND')])

    def test_open_window_asks_by_itself(self):
        path = str(self.watched / 'eicar.com')
        agent, scan = self.scanning_agent({'infected': [(path, 'Eicar FOUND')], 'infected_found': True,
                                           'errors': False, 'warnings': False, 'stopped': False, 'scanned': 1})
        agent.gui_running = lambda: True
        with scan:
            agent.scan([path])
        self.open_application.assert_not_called()
        self.notify.assert_called_once()

    def test_one_notification_follows_a_download_from_waiting_to_result(self):
        path = str(self.watched / 'setup.zip')
        clean = {'infected': [], 'infected_found': False, 'errors': False, 'warnings': False,
                 'stopped': False, 'scanned': 1}
        agent, scan = self.scanning_agent(clean)
        partial = path + '.part'
        firefox_temporary = str(self.watched / 'Xq7Lp2.part')
        agent.announce([partial, firefox_temporary])
        agent.announce([partial, firefox_temporary])  # once per download
        messages = [call.args[1] for call in self.notify.call_args_list]
        self.assertEqual(len(messages), 2)
        # Browsers use temporary, sometimes random names: none are shown while waiting.
        self.assertTrue(all(message.startswith('Waiting for a download to finish.') for message in messages))
        self.assertEqual(self.notify.call_args_list[0].kwargs['replace'], f'download:{partial}')
        agent.announce([partial])  # Firefox renamed its temporary file
        agent.monitor.came_from.return_value = partial
        self.notify.reset_mock()

        def slow_run(service, *_args, **_kwargs):
            time.sleep(.3)
            service.result = clean

        with patch('core.monitor_agent.SLOW_CHECK', .05), \
                patch('core.monitor_agent.ScanService.run', autospec=True, side_effect=slow_run):
            agent.scan([path])
        titles = [call.args[0] for call in self.notify.call_args_list]
        self.assertEqual(titles, ['LibreWard — checking', 'LibreWard — new files checked'])
        # "Checking…" updates the "Waiting"; the result is a new notification that
        # GNOME shows, and the download's notification and the vanished temporary one close.
        self.assertEqual([call.kwargs['replace'] for call in self.notify.call_args_list],
                         [f'download:{partial}', None])
        self.assertEqual({call.args[0] for call in self.close_notification.call_args_list},
                         {f'download:{partial}', f'download:{firefox_temporary}'})
        agent.monitor.came_from.return_value = None
        with scan:  # quick checks say nothing until the result
            self.notify.reset_mock()
            agent.scan([str(self.watched / 'small.txt')])
        self.assertEqual([call.args[0] for call in self.notify.call_args_list], ['LibreWard — new files checked'])

    def test_threats_only_mutes_everything_but_dangerous_files(self):
        path = str(self.watched / 'file.zip')
        agent, scan = self.scanning_agent({'infected': [], 'infected_found': False, 'errors': False,
                                           'warnings': False, 'stopped': False, 'scanned': 1})
        agent.config['notify_threats_only'] = True
        agent.monitor.came_from.return_value = None
        agent.announce([path + '.part'])
        with scan:
            agent.scan([path])
        self.notify.assert_not_called()
        agent, scan = self.scanning_agent({'infected': [(path, 'Eicar FOUND')], 'infected_found': True,
                                           'errors': False, 'warnings': False, 'stopped': False, 'scanned': 1})
        agent.config['notify_threats_only'] = True
        agent.monitor.came_from.return_value = None
        with scan:
            agent.scan([path])
        self.assertEqual(self.notify.call_args.args[0], '⚠ LibreWard — dangerous file found')

    def test_files_saved_anywhere_by_a_browser_are_checked(self):
        agent = self.agent()
        agent.config = {'watch_folders_enabled': True, 'watched_folders': [str(self.watched)]}
        agent.monitor = Mock()
        saved = self.root / 'Elsewhere' / 'setup.zip'
        saved.parent.mkdir()
        saved.write_text('data')
        history = Mock()
        history.new_downloads.return_value = [str(saved), str(self.root / 'gone.zip')]
        with patch('core.browser_downloads.DownloadHistory', return_value=history):
            agent.follow_downloads(100)  # starts from now: earlier downloads are not checked
            history.new_downloads.assert_not_called()
            agent.follow_downloads(105)  # within the interval
            history.new_downloads.assert_not_called()
            agent.follow_downloads(111)
        agent.monitor.changed.assert_called_once_with(str(saved), finished=True,
                                                     reason="in a browser's list of downloads")
        agent.config['follow_download_folders'] = False
        agent.follow_downloads(200)
        self.assertEqual(history.new_downloads.call_count, 1)

    def test_agent_keeps_its_own_clamd_between_checks_and_releases_it(self):
        from backends.base import RuntimeInfo
        installed = StartupStatus(RuntimeInfo('system-path', 'clamscan', 'freshclam', 'ClamAV 1.5.2', '1.5.2'),
                                  True, True, False, True, clamd_path='/usr/sbin/clamd')
        sessions = []

        def run(service, *_args, parallel=False, session=None, **_kwargs):
            sessions.append((parallel, session))
            service.result = {'infected': [], 'errors': False, 'warnings': False, 'stopped': False, 'scanned': 1}

        agent, _scan = self.scanning_agent({})
        agent.status = installed
        with patch('core.monitor_agent.ScanService.run', autospec=True, side_effect=run), \
                patch('core.clamd.ClamdSession.close') as close:
            agent.scan([str(self.watched / 'a')])
            agent.scan([str(self.watched / 'b')])
            self.assertTrue(all(parallel for parallel, _session in sessions))
            self.assertIs(sessions[0][1], sessions[1][1])  # the database stays loaded
            agent.release_clamd()
            close.assert_not_called()
            agent.clamd_used -= monitor_agent.CLAMD_IDLE + 1
            agent.release_clamd()
            close.assert_called_once()
            self.assertIsNone(agent.clamd)
            # Changed scan limits start a new daemon.
            agent.scan([str(self.watched / 'c')])
            first = agent.clamd
            agent.config['scan_profile'] = 'extended'
            agent.scan([str(self.watched / 'd')])
            self.assertIsNot(agent.clamd, first)

    def test_threats_whose_file_is_gone_are_forgotten(self):
        kept = self.watched / 'still-here.exe'
        kept.write_text('sample')
        agent = self.agent()
        agent.update_state(threats=[{'path': str(kept), 'threat': 'A FOUND', 'time': 1},
                                    {'path': str(self.watched / 'deleted.com'), 'threat': 'B FOUND', 'time': 2}])
        agent.forget_removed_threats()
        self.assertEqual([entry['path'] for entry in read_state()['threats']], [str(kept)])

    def test_cancelled_download_loses_its_waiting_notification(self):
        agent = self.agent()
        agent.config = {}
        with patch('core.monitor_agent.time.monotonic', return_value=100):
            agent.announce(['/d/setup.zip.part'])
            agent.announce([])  # gone: cancelled, or moved to a folder chosen in Firefox
        with patch('core.monitor_agent.time.monotonic', return_value=110):
            agent.announce([])
        self.close_notification.assert_not_called()  # the download list may still find it
        with patch('core.monitor_agent.time.monotonic', return_value=100 + monitor_agent.STALE_DOWNLOAD + 1):
            agent.announce([])
        self.close_notification.assert_called_once_with('download:/d/setup.zip.part')
        self.assertEqual(agent.announced, {})

    def test_each_check_is_logged_with_its_reason(self):
        agent, scan = self.scanning_agent({'infected': [], 'errors': False, 'warnings': False,
                                           'stopped': False, 'scanned': 1})
        agent.monitor.reason.return_value = "in a browser's list of downloads"
        with scan:
            agent.scan([str(self.watched / 'setup.zip')])
        self.assertIn("Checking setup.zip (in a browser's list of downloads).", self.logged)

    def test_checking_due_at_the_same_moment_never_replaces_the_result(self):
        # A check finishing right at the two-second mark: the "Checking…" timer fires
        # while the result is sent and must find the check already done.
        events, timers = [], []
        make_event = threading.Event  # before it is patched below

        def event():
            events.append(make_event())
            return events[-1]

        class Timer:
            def __init__(self, _delay, function):
                timers.append(function)
                self.daemon = True

            def start(self):
                pass

            def cancel(self):
                pass

        path = str(self.watched / 'eicar.com')
        agent, scan = self.scanning_agent({'infected': [(path, 'Eicar FOUND')], 'infected_found': True,
                                           'errors': False, 'warnings': False, 'stopped': False, 'scanned': 1})
        sent_while_running = []

        def notify(title, *_args, **_kwargs):
            sent_while_running.append((title, events[0].is_set()))
            return True

        self.notify.side_effect = notify
        with patch('core.monitor_agent.threading.Event', side_effect=event), \
                patch('core.monitor_agent.threading.Timer', Timer), scan:
            agent.scan([path])
        self.assertEqual(sent_while_running, [('⚠ LibreWard — dangerous file found', True)])
        timers[0]()  # the late "Checking…"
        self.assertEqual(len(sent_while_running), 1)

    def test_an_unfinished_check_never_leaves_checking_behind(self):
        agent, scan = self.scanning_agent({'infected': [], 'errors': True, 'stopped': False, 'scanned': 0})
        path = str(self.watched / 'gone.zip')  # deleted while it was checked
        with scan:
            agent.scan([path])
        self.close_notification.assert_called_once_with(f'check:{path}')

    def test_failed_scans_retry_and_notify_once(self):
        agent, scan = self.scanning_agent({'infected': [], 'errors': True, 'stopped': False, 'scanned': 0})
        path = str(self.watched / 'file')
        with scan:
            for _attempt in range(4):
                agent.scan([path])
        agent.monitor.changed.assert_called_with(path, retry=True)
        self.assertEqual(agent.monitor.changed.call_count, 4)
        self.assertGreater(agent.retry_at, time.monotonic())
        self.assertEqual(self.notify.call_count, 1)
        self.assertEqual(self.notify.call_args.args[0], '⚠ LibreWard — automatic scan failed')

    def test_undelivered_warnings_are_sent_again_later(self):
        agent = self.agent()
        self.notify.return_value = False
        agent.send('⚠ LibreWard — dangerous file found', 'eicar.com', True)
        agent.send('LibreWard — new files checked', 'clean', False)
        self.assertEqual(len(agent.undelivered), 1)
        agent.retry_notifications()
        self.assertEqual(self.notify.call_count, 2)  # not before the retry interval
        self.notify.return_value = True
        queued, _next, title, message = agent.undelivered[0]
        agent.undelivered = [(queued, 0, title, message)]
        agent.retry_notifications()
        self.assertEqual(self.notify.call_count, 3)
        self.assertEqual(agent.undelivered, [])
        agent.undelivered = [(time.monotonic() - monitor_agent.NOTIFICATION_GIVE_UP - 1, 0, title, message)]
        agent.retry_notifications()
        self.assertEqual(agent.undelivered, [])
        self.assertEqual(self.notify.call_count, 3)

    def test_agent_runs_once_and_ends_when_monitoring_is_turned_off(self):
        self.save(watch_folders_enabled=True, watched_folders=[str(self.watched)])
        agent = self.agent()
        with patch('core.monitor_agent.check_startup', return_value=self.ready):
            thread = threading.Thread(target=agent.run)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while read_state().get('status') != 'watching' and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertEqual(read_state()['status'], 'watching')
                self.assertTrue(read_state()['running'])
                self.assertEqual(self.agent().run(), 0)  # a second agent does not start
                self.assertIn('already running', self.logged[-1])
                self.save(watch_folders_enabled=False, watched_folders=[str(self.watched)])
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            finally:
                agent.stop()
                thread.join(timeout=5)
        state = read_state()
        self.assertEqual(state['status'], 'off')
        self.assertFalse(state['running'])
        lock = monitor_agent.backend.acquire_instance_lock(monitor_agent.lock_file())
        self.assertIsNotNone(lock)
        lock.close()

    def test_missing_watchdog_is_reported_and_not_restarted(self):
        self.save(watch_folders_enabled=True, watched_folders=[str(self.watched)])
        with patch('core.monitor_agent.missing_components', return_value={'watchdog': 'No module'}), \
                patch('core.dependencies.backend.dependency_install_commands',
                      return_value=['sudo dnf install python3-watchdog']):
            self.assertEqual(self.agent().run(), monitor_agent.MISSING_COMPONENT_EXIT)
        state = read_state()
        self.assertEqual(state['status'], 'error')
        self.assertIn('sudo dnf install python3-watchdog', state['message'])
        self.assertFalse(state['running'])

    def test_notification_availability_is_recorded(self):
        agent = self.agent()
        with patch.object(monitor_agent.backend, 'notifications_available', return_value=False), \
                patch('core.monitor_agent.check_startup', return_value=self.ready):
            agent.check_status()
        self.assertIs(read_state()['notifications'], False)

    def test_a_changed_policy_is_read_without_a_settings_change(self):
        self.save(scheduled_scan='off')
        agent = self.agent()
        signature = [None]
        with patch('core.monitor_agent.policy_signature', side_effect=lambda: signature[0]):
            agent.reload_config()
            self.assertEqual(agent.config['scheduled_scan'], 'off')
            signature[0] = (1, 2)
            with patch('core.monitor_agent.load_config', return_value={'scheduled_scan': 'weekly'}):
                agent.reload_config()
        self.assertEqual(agent.config['scheduled_scan'], 'weekly')

    def test_unreadable_settings_keep_the_previous_ones(self):
        self.save(watch_folders_enabled=True, watched_folders=[str(self.watched)])
        agent = self.agent()
        agent.reload_config()
        self.config_file.write_text('{"watch_folders_')
        agent.reload()
        agent.reload_config()
        self.assertTrue(agent.config['watch_folders_enabled'])

    def test_files_waiting_at_shutdown_are_checked_after_restart(self):
        path = self.watched / 'late.zip'
        path.write_text('downloaded just before logout')
        agent = self.agent()
        agent.scanning = [str(path)]
        agent._stop_monitor()
        self.assertEqual(read_state()['pending'], [str(path)])
        restarted = self.agent()
        with patch('core.folder_watch.FolderMonitor.start'):
            restarted.start_monitor(monitor_settings({'watch_folders_enabled': True,
                                                      'watched_folders': [str(self.watched)]}))
        self.assertIn(str(path), restarted.monitor.pending)
        self.assertEqual(read_state()['pending'], [])

    def test_database_refresh_uses_the_newest_attempt_of_gui_and_agent(self):
        agent = self.agent()
        agent.status = self.ready
        agent.database_checked = float('-inf')
        agent.config = {'database_auto_update_at': 0}
        agent.state['database_update_at'] = time.time()
        with patch('core.monitor_agent.own_database_needs_refresh', return_value=True), \
                patch('core.monitor_agent.run_freshclam_update') as update:
            agent.maybe_update_database()
        update.assert_not_called()
        agent.database_checked = float('-inf')
        agent.state['database_update_at'] = 0
        with patch('core.monitor_agent.own_database_needs_refresh', return_value=True), \
                patch('core.monitor_agent.run_freshclam_update', return_value=(True, '')) as update:
            agent.maybe_update_database()
            agent.database_thread.join(timeout=3)
        update.assert_called_once_with('freshclam', wait=False)
        self.assertTrue(read_state()['database_update_ok'])

    # ── scheduled scans ─────────────────────────────────────────────

    def scheduled_agent(self, result, schedule='weekly'):
        agent = self.agent()
        agent.config = {'scheduled_scan': schedule}
        agent.status = self.ready
        agent.schedule_not_before = 0
        calls = []
        self.system_check = {'time': 1, 'findings': [], 'checks': ['Hidden programs']}
        checker = patch('core.system_check.run_system_check', side_effect=lambda: self.system_check)
        checker.start()
        self.addCleanup(checker.stop)

        def run(service, roots, *_args, **kwargs):
            calls.append((roots, kwargs))
            service.result = result

        return agent, calls, patch('core.monitor_agent.ScanService.run', autospec=True, side_effect=run)

    def finish(self, agent):
        agent.scheduled_thread.join(timeout=3)
        agent.run_schedule()  # the agent's loop reports the result

    def test_schedule_is_due_after_its_interval_or_when_never_run(self):
        week = monitor_agent.SCHEDULES['weekly']
        self.assertFalse(monitor_agent.scheduled_scan_due(1000, None, None))
        self.assertTrue(monitor_agent.scheduled_scan_due(1000, None, week))
        self.assertFalse(monitor_agent.scheduled_scan_due(1000 + week - 1, 1000, week))
        self.assertTrue(monitor_agent.scheduled_scan_due(1000 + week, 1000, week))
        # The clock was set back: never wait for a date that is far away.
        self.assertTrue(monitor_agent.scheduled_scan_due(1000, 5000, week))
        self.assertIsNone(monitor_agent.scheduled_interval({'scheduled_scan': 'hourly'}))
        self.assertTrue(monitor_agent.agent_needed({'scheduled_scan': 'daily'}))
        self.assertFalse(monitor_agent.agent_needed({'scheduled_scan': 'off'}))

    def test_scheduled_quick_scan_runs_once_and_is_recorded(self):
        agent, calls, scan = self.scheduled_agent({'infected': [], 'errors': False, 'warnings': False,
                                                   'stopped': False, 'scanned': 120})
        with scan, patch('core.quick_scan.quick_scan_targets', return_value=[str(self.watched)]):
            agent.run_schedule()
            self.assertIsNotNone(read_state()['scheduled_scan_running'])
            self.finish(agent)
            agent.run_schedule()  # not due again for a week
        self.assertEqual(calls, [([str(self.watched)], {'parallel': False})])
        state = read_state()
        self.assertIsNone(state['scheduled_scan_running'])
        self.assertEqual(state['scheduled_scan']['outcome'], 'No threats found')
        self.assertEqual(state['scheduled_scan']['files'], 120)
        title, message = self.notify.call_args.args
        self.assertEqual(title, 'LibreWard — scheduled scan')
        self.assertIn('Checked: 120 file(s).', message)
        # Remembered after a restart, so the next start does not scan again.
        self.assertEqual(self.agent().state['scheduled_scan'], state['scheduled_scan'])

    def test_scheduled_scan_waits_after_login_and_for_the_antivirus_engine(self):
        agent, calls, scan = self.scheduled_agent({'errors': False})
        agent.schedule_not_before = time.monotonic() + 60
        with scan:
            agent.run_schedule()
            self.assertIsNone(agent.scheduled_thread)
            agent.schedule_not_before = 0
            agent.status = None
            agent.run_schedule()
        self.assertIsNone(agent.scheduled_thread)
        self.assertEqual(calls, [])
        self.assertIn('antivirus engine', read_state()['scheduled_scan_waiting'])
        # A virus database refresh that is running finishes first.
        agent.status = self.ready
        refresh = threading.Event()
        agent.database_thread = threading.Thread(target=refresh.wait, args=(3,))
        agent.database_thread.start()
        with scan:
            agent.run_schedule()
            self.assertIsNone(agent.scheduled_thread)
            refresh.set()
            agent.database_thread.join(3)
            agent.run_schedule()
            self.finish(agent)
        self.assertEqual(len(calls), 1)

    def test_scheduled_scan_threat_is_asked_about_like_a_new_file(self):
        path = str(self.watched / 'old.exe')
        agent, _calls, scan = self.scheduled_agent({'infected': [(path, 'Win.Test FOUND')], 'infected_found': True,
                                                    'errors': False, 'stopped': False, 'scanned': 3})
        agent.config['notify_threats_only'] = True
        with scan, patch('core.quick_scan.quick_scan_targets', return_value=[str(self.watched)]):
            agent.run_schedule()
            self.finish(agent)
        self.assertEqual(read_state()['threats'][0]['path'], path)
        title, message = self.notify.call_args.args
        self.assertIn('dangerous file found', title)
        self.assertIn('old.exe', message)
        self.open_application.assert_called_once_with('--threats')

    def test_system_check_runs_after_a_scheduled_scan_and_warns_about_findings(self):
        agent, _calls, scan = self.scheduled_agent({'infected': [], 'errors': False, 'warnings': False,
                                                    'stopped': False, 'scanned': 5})
        agent.config['notify_threats_only'] = True  # suspicious findings are still reported
        self.system_check = {'time': 1, 'checks': ['Hidden programs'], 'findings': [
            {'check': 'hidden-process', 'title': 'A running program is hidden', 'detail': 'Process 50', 'where': ''}]}
        with scan, patch('core.quick_scan.quick_scan_targets', return_value=[str(self.watched)]):
            agent.run_schedule()
            self.finish(agent)
        self.assertEqual(read_state()['system_check'], {'time': 1, 'titles': ['A running program is hidden']})
        title, message = self.notify.call_args.args
        self.assertIn('something suspicious', title)
        self.assertIn('A running program is hidden', message)
        self.assertTrue(self.notify.call_args.kwargs['warning'])
        self.assertTrue(any('Suspicious: A running program is hidden' in line for line in self.logged))

    def test_unfinished_scheduled_scan_is_tried_again_in_an_hour(self):
        agent, calls, scan = self.scheduled_agent({'errors': True, 'stopped': False})
        with scan, patch('core.quick_scan.quick_scan_targets', return_value=[str(self.watched)]):
            agent.run_schedule()
            self.finish(agent)
            agent.run_schedule()
        self.assertEqual(len(calls), 1)
        self.assertGreater(agent.schedule_not_before, time.monotonic() + 59 * 60)
        state = read_state()
        self.assertNotIn('scheduled_scan', state)
        self.assertIsNotNone(state['scheduled_scan_error'])
        self.notify.assert_not_called()

    def test_agent_for_scheduled_scans_only_needs_no_folder_watching(self):
        self.save(scheduled_scan='weekly')
        agent = self.agent()
        with patch('core.monitor_agent.check_startup', return_value=self.ready),                 patch('core.monitor_agent.missing_components', return_value={'watchdog': 'No module'}):
            thread = threading.Thread(target=agent.run)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while read_state().get('status') != 'off' and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(read_state()['running'])
                self.assertIsNone(agent.monitor)
                self.save(scheduled_scan='off')
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            finally:
                agent.stop()
                thread.join(timeout=5)
        self.assertFalse(read_state()['running'])


if __name__ == '__main__':
    unittest.main()
