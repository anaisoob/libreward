"""Structured firewall rule editor; command execution belongs to the backend."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QVBoxLayout,
)

from core.firewall import FirewallRule


class FirewallRuleDialog(QDialog):
    def __init__(self, parent, tool_name, zones=(), networks=()):
        super().__init__(parent)
        self.tool_name = tool_name
        self.setWindowTitle(f'Add {tool_name} rule')
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        description = QLabel('Choose which connections this rule allows or blocks. You will review the change before system authorization.')
        description.setWordWrap(True)
        layout.addWidget(description)
        form = QFormLayout()
        self.action = self.combo(('Allow', 'allow'), ('Block', 'deny'))
        self.direction = self.combo(('Incoming — connections to this computer', 'in'))
        if tool_name == 'UFW':
            self.direction.addItem('Outgoing — connections from this computer', 'out')
            self.direction.addItem('Incoming and outgoing', 'both')
        self.scope = self.combo(('LAN — specific network', 'lan'), ('Internet / all addresses — includes LAN', 'internet'))
        self.subnet = QLineEdit()
        self.subnet.setPlaceholderText('Your LAN CIDR, e.g. 192.168.1.0/24 or fd12:3456::/64')
        self.detected_networks = QComboBox()
        for interface, network in networks:
            self.detected_networks.addItem(f'{interface} · {network}', network)
        if networks:
            self.subnet.setText(networks[0][1])
        else:
            self.detected_networks.addItem('No connected network detected — enter CIDR below', '')
        self.detected_networks.currentIndexChanged.connect(self.select_detected_network)
        self.protocol = self.combo(('TCP', 'tcp'), ('UDP', 'udp'))
        self.port = QLineEdit()
        self.port.setPlaceholderText('Destination port, e.g. 22 or 8000-8010')
        self.zone = QComboBox()
        self.zone.setEditable(True)
        self.zone.addItems(list(zones))
        self.zone.setEditText('')
        self.zone.lineEdit().setPlaceholderText('Choose the zone shown for your connection')
        self.lifetime = self.combo(('Apply now — until reload/restart', 'runtime'), ('Save only — applies after reload/restart', 'permanent'))
        for label, widget in (('Action', self.action), ('Direction', self.direction),
                              ('Network', self.scope), ('Detected networks', self.detected_networks), ('LAN network', self.subnet),
                              ('Protocol', self.protocol), ('Destination port', self.port)):
            form.addRow(label, widget)
        if tool_name == 'firewalld':
            form.addRow('Zone', self.zone)
            form.addRow('Apply to', self.lifetime)
        layout.addLayout(form)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.hint)
        self.scope.currentIndexChanged.connect(self.update_scope)
        self.update_scope()
        note = QLabel('Existing rules still apply. Allowing LAN does not remove an existing rule that allows the same port from all addresses. UFW rules are saved; inactive UFW rules apply when it is enabled.')
        note.setWordWrap(True)
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText('Review rule')
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def combo(*items):
        combo = QComboBox()
        for text, value in items:
            combo.addItem(text, value)
        return combo

    def select_detected_network(self):
        network = self.detected_networks.currentData()
        if network:
            self.subnet.setText(network)

    def update_scope(self):
        lan = self.scope.currentData() == 'lan'
        self.subnet.setEnabled(lan)
        self.detected_networks.setEnabled(lan)
        self.hint.setText('Detected networks include connected adapters and may include VPNs or virtual networks. Check the selected network; you can edit its CIDR. A single CIDR covers one IP family; add a separate rule for IPv4 and IPv6 when needed.' if lan else
                          'This rule matches all peer addresses, including both LAN and Internet. It does not isolate Internet traffic from LAN traffic.')

    def rule(self):
        return FirewallRule(
            action=self.action.currentData(), direction=self.direction.currentData(),
            scope=self.scope.currentData(), protocol=self.protocol.currentData(),
            port=self.port.text(), subnet=self.subnet.text(),
            zone=self.zone.currentText() if self.tool_name == 'firewalld' else '',
            lifetime=self.lifetime.currentData(),
        ).validated()
