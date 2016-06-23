%global with_check 0

Name:           sgmanager
Version:        1.4.3
Release:        1%{?dist}
Summary:        Tooling for EC2 security groups management

Group:          Development/Libraries
License:        BSD
URL:            https://github.com/gooddata/sgmanager
Source0:        sgmanager.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
BuildRequires:  python2-devel python-setuptools-devel
Requires:       python-requests python-boto PyYAML
%if 0%{?rhel} < 7
Requires:       python-argparse
%endif

%description
Tooling for management of security groups. Load local configuration, load
remote groups and apply differences.

%prep
%setup -q -n sgmanager

%build
%{__python} setup.py build

%install
%{__rm} -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}

%if 0%{?with_check}
%check
%{__python} setup.py test
%endif #with_check

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{python_sitelib}/*.egg-info
%{python_sitelib}/sgmanager
/usr/bin/sgmanager
