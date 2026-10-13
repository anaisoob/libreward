# Fedora and openSUSE, for example through the openSUSE Build Service.
Name:           libreward
Version:        0.3.0
Release:        1%{?dist}
Summary:        Simple virus scanning, firewall and Internet protection for Linux desktops
License:        GPL-2.0-or-later
URL:            https://github.com/anaisoob/libreward
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  make
BuildRequires:  python3
Requires:       python3
# Generated Python provides work on Fedora (python3-pyside6) and openSUSE (python3XX-pyside6).
Requires:       python3dist(pyside6)
Requires:       polkit
Requires:       systemd
Recommends:     clamav
Recommends:     NetworkManager
Suggests:       firewalld

%description
LibreWard is a cross-platform security and privacy desktop application. On Linux
it scans files with ClamAV, manages UFW or firewalld, and blocks unwanted website
domains with a local DNS filter in front of NetworkManager or systemd-resolved.

%prep
%autosetup -n %{name}-%{version}

%build
# Pure Python; byte-compiled during installation.

%install
%make_install PREFIX=%{_prefix} PYTHON=%{__python3}

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/libreward
%{_datadir}/libreward/
%{_datadir}/applications/libreward.desktop
%{_datadir}/icons/hicolor/scalable/apps/libreward.svg
%{_datadir}/icons/hicolor/256x256/apps/libreward.png

%changelog
* Tue Oct 13 2026 anaisoob <anaisoob@tutamail.com> - 0.3.0-1
- Initial package.
