%{!?kversion: %{expand: %%define kversion %(uname -r)}}
%define kmod_name utun
%define kverrel %{kversion}
%define kvariants ""
%define kvariant ""
%global _use_internal_dependency_generator 0

Name:       kmod-%{kmod_name}
Version:    1.0
Release:    1%{?dist}
Summary:    Driver for tunneling IPv6 over IPv4UDP
License:    GPLv2
Packager:   CITC IPv6 Tunnel Broker team / tunnelbroker@citc.gov.sa
Group:      System Environment/Kernel
URL:        http://www.ipv6.sa/tunnelbroker
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root
Source0:    %{kmod_name}-%{version}.tar.bz2
# BuildArchitectures: noarch i386 i686 ia64 ppc64 s390x x86_64
BuildRequires:  redhat-rpm-config gcc make rpm-build kernel-devel kernel-headers
# ExclusiveArch:  noarch i386 i686 ia64 ppc64 s390x x86_64

%description
  Kernel module for IPv6 over UDP/IPv4 tunneling. User space programs control
  creation of interfaces. Packets are completely forwarded in kernel mode.

# Disable the building of the debug package(s).
%define debug_package %{nil}

# Define the filter.
%define __find_requires sh %{_builddir}/%{buildsubdir}/filter-requires.sh
# sh /usr/lib/rpm/redhat/kmodtool rpmtemplate  %{kversion} ""

%prep
%setup -q -c -T -a 0

    %{__cp} -a %{kmod_name}-%{version} _kmod_build_$kvariant
    echo "/usr/lib/rpm/redhat/find-requires | %{__sed} -e '/^ksym.*/d'" > filter-requires.sh
    cat >kmod-%{kmod_name}.conf <<EOF
#
# kmod-%{kmod_name}.conf
#
override %{kmod_name} * weak-updates/%{kmod_name}"
EOF

%files
%defattr(644,root,root,755)
%config(noreplace) /etc/depmod.d/kmod-%{kmod_name}.conf
/lib/modules/%{kversion}/extra/%{kmod_name}/%{kmod_name}.ko

%build
    KSRC=%{_usrsrc}/kernels/%{kversion}
    %{__make} -C "${KSRC}" %{?_smp_mflags} modules M=$PWD/_kmod_build_

%install
    %{__rm} -rf %{buildroot}
    export INSTALL_MOD_PATH=%{buildroot}
    export INSTALL_MOD_DIR=extra/%{kmod_name}

    KSRC=%{_usrsrc}/kernels/%{kversion}
    %{__make} -C "${KSRC}" modules_install M=$PWD/_kmod_build_
    %{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
    %{__install} kmod-%{kmod_name}.conf %{buildroot}%{_sysconfdir}/depmod.d/

# Set the module(s) to be executable, so that they will be stripped when packaged.
    find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;

%post          -n kmod-utun
if [ -e "/boot/System.map-%{kversion}" ]; then
    /sbin/depmod -aeF "/boot/System.map-%{kversion}" "%{kversion}" > /dev/null || :
fi

modules=( $(find /lib/modules/%{kversion}/extra/%{kmod_name} | grep '\.ko$') )
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "${modules[@]}"     | /sbin/weak-modules --add-modules --no-initramfs
fi

%preun         -n kmod-utun
rpm -ql kmod-utun-%{version}-%{release}.%{_target_cpu} | grep '\.ko$' > /var/run/rpm-kmod-%{kmod_name}-modules

%postun        -n kmod-utun
if [ -e "/boot/System.map-%{kversion}" ]; then
    /sbin/depmod -aeF "/boot/System.map-%{kversion}" "%{kversion}" > /dev/null || :
fi

modules=( $(cat /var/run/rpm-kmod-%{kmod_name}-modules) )
rm /var/run/rpm-kmod-%{kmod_name}-modules
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "${modules[@]}"     | /sbin/weak-modules --remove-modules --no-initramfs
fi

%clean
    %{__rm} -rf %{buildroot}

%changelog
* Wed Sep 20 2011 - 1.0-1.el6
- Initial version.
