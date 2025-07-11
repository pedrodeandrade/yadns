%define name            cryptopANT
%define version         1.3.1
BuildRoot:              %{_tmppath}/%{name}-%{version}-build
Summary:                IP address anonymization library and utils
License:                GPL
URL:                    http://ant.isi.edu/software/cryptopANT/index.html
Name:                   %{name}
Version:                %{version}
Release:                1
Source:                 %{name}-%{version}.tar.gz
Packager:               yuri@isi.edu
Prefix:                 /usr
Group:                  System/Libraries
BuildRequires:          gcc glibc-headers 
BuildRequires:          openssl-devel >= 1.3.0
BuildRequires:          autoconf automake libtool
Requires:               openssl >= 1.3.0

%description
cryptopANT is a library for ip address anonymization.  It implements a
widely used prefix-preserving technique known as "cryptopan".  This is
ANT's project implementation of this technique for anonymization of ipv4
and ipv6 addresses.

%prep
%setup -q

%build
%configure --with-scramble_ips
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=%{buildroot}
libtool --finish %{_libdir}

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_libdir}/*.so.*
%{_libdir}/*.a
%{_bindir}/scramble_ips
%{_mandir}/man3/*

%changelog
* Mon Mar 25 2024 Yuri Pradkin <yuri@isi.edu> - 1.4.1
- Fixed blowfish regression introduced in 1.4.0
