Name: obdal
Version: 0.2.2
Release: %(echo $RELEASE)
Url: https://github.com/oceanbase/opendal
Summary: .

Group: oceanbase-devel/dependencies
License: Apache 2.0

%undefine _missing_build_ids_terminate_build
%define _build_id_links compat

# disable check-buildroot
%define __arch_install_post %{nil}

%define _prefix /usr/local/oceanbase/deps/devel
%define _src obdal

%define _buliddir %{_topdir}/BUILD
%define _tmpdir %{_buliddir}/_tmp
%define _root_dir $RPM_BUILD_ROOT%{_prefix}

%define debug_package %{nil}
%define __strip /bin/true

%description
.

%build
rm -rf %{_root_dir}
rm -rf %{_tmpdir}
mkdir -p %{_tmpdir}


cd $OLDPWD/bindings/c
rm -rf build
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=%{_tmpdir} -DCMAKE_BUILD_TYPE=RelWithDebInfo
make
make install

%install
mkdir -p %{_root_dir}
cp -r %{_tmpdir}/lib %{_tmpdir}/include %{_root_dir}

%files
%defattr(-,root,root)
%{_prefix}

%changelog
* Wed Dec 11 2024 oceanbase
- add spec of obdal
