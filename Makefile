#
# Install the DDTB scripts and files
#
# Initial alpha version checking dkms/rpmbuild, python AES-crypto and
# stuff like that by IPv6 Tunnel Broker team / CITC.
#
# Kernel module version. Used by DKMS.
KMODVER=1.0

ifndef PREFIX
	PREFIX=/usr/local
endif

ifndef PY_EXEC
	PY_EXEC=$(shell which python)
endif

ifndef DKMS
	DKMS=/usr/sbin/dkms
endif

.PHONY: kernelmodule

# all: pythonmodule kernelmodule
all: kernelmodule pythonmodule

clean:
	@echo "Cleanup python build directories"
	rm -rf build dist src/*.egg-info
	@echo "Cleanup built kernel module"
	make -C utun-dkms clean

test_prereq:
	@if [ -f /etc/redhat-release ]; then \
            missing_packages=0; \
            for i in kernel-headers gcc rpm-build redhat-rpm-config make kernel-devel iptables-devel \
                     python-setuptools python-devel python-crypto python-cracklib mysql-server mysql-devel; do \
                this_miss=`rpm -qi $$i >/dev/null 2>&1; echo $$?`; \
                missing_packages=`expr $$missing_packages + $$this_miss`; \
            done; \
            if [ $$missing_packages -ne 0 ]; then \
                echo " "; \
                echo "***"; \
                echo "  You are missing $$missing_packages of following required packages:"; \
                echo "    kernel-headers gcc rpm-build redhat-rpm-config make kernel-devel iptables-devel"; \
                echo "    python-setuptools python-devel python-crypto python-cracklib mysql-server mysql-devel"; \
                echo " "; \
                echo "  ddtb and utun kernel module can't install without these."; \
                echo "***"; \
                echo " "; \
                exit 1; \
            fi; \
        fi

	@if [ -f /etc/debian_version ]; then \
            missing_packages=0; \
            for i in linux-headers-`uname -r` gcc make dkms libmysqlclient-dev xtables-addons-common \
                     python-setuptools python-dev python-crypto python-cracklib mysql-server; do \
                this_miss=`dpkg -s $$i >/dev/null 2>&1; echo $$?`; \
                missing_packages=`expr $$missing_packages + $$this_miss`; \
            done; \
            if [ $$missing_packages -ne 0 ]; then \
                echo " "; \
                echo "***"; \
                echo "  You are missing $$missing_packages of following required packages:"; \
                echo "    linux-headers-`uname -r` gcc make libmysqlclient-dev python-setuptools python-dev"; \
                echo "    dkms python-crypto python-cracklib mysql-server xtables-addons-common"; \
                echo " "; \
                echo "  ddtb and utun kernel module can't install without these."; \
                echo "***"; \
                echo " "; \
                exit 2; \
            fi; \
        fi

	@if [ ! -z $(PY_EXEC) -a -x $(PY_EXEC) ]; then \
            python_crypto=`$(PY_EXEC) -c "exec(\"import sys\\ntry: from Crypto.Cipher import AES\\nexcept ImportError:\\n  sys.exit(1)\")"; echo $$?`; \
            if [ $$python_crypto -ne 0 ]; then \
                echo " "; \
                echo "***"; \
                echo "  Your python-installation does not have AES from Crypto.Cipher."; \
                echo "  Install python 2.6 or newer and python-crypto package, then try again."; \
                echo "***"; \
                echo " "; \
                exit 3; \
            fi; \
        else \
                echo " "; \
                echo "***"; \
                echo "  Where is your python now? Can't find it. Please install and check it's in your path."; \
                echo "***"; \
                echo " "; \
                exit 4; \
        fi

	@echo "Prerequisites met, good."

kernelmodule: test_prereq
	@echo " "
	@echo "***"
	@echo "  Running 'make kernelmodule'."
	@echo "***"
	@if ([ ! -z $(DKMS) ] && [ -x $(DKMS) ]); then \
            echo " "; \
            echo "***"; \
            echo "  Running dkms add/build cycle."; \
            echo "***"; \
            cp -r utun-dkms /usr/src/utun-$(KMODVER); \
            dkms_add=`$(DKMS) add -m utun -v $(KMODVER) -k \`uname -r\` >/dev/null 2>&1; echo $$?`; \
            if [ $$dkms_add -ne 0 ]; then \
                echo " "; \
                echo "***"; \
                echo "  $(DKMS) add -m utun -v $(KMODVER) failed: this version is already installed."; \
                echo "  Try '$(DKMS) remove -m utun -v $(KMODVER) -k `uname -r`' or"; \
                echo "      '$(DKMS) remove -m utun -v $(KMODVER) --all' before adding this version again."; \
                echo "***"; \
                echo " "; \
            else \
                $(DKMS) build -m utun -v $(KMODVER) >/dev/null 2>&1; \
            fi; \
        elif ([ -x /usr/bin/rpmbuild ] && [ ! -f $(DKMS) ]); then \
            echo " "; \
            echo "***"; \
            echo "  Running rpmbuild. See build-out.log and build-err.log for details."; \
            echo "***"; \
            rpmbuild --define '_topdir $(PWD)/utun-rpm' -ba --target=`uname -m` utun-rpm/SPECS/kmod-utun.spec >build-out.log 2> build-err.log; \
        else \
            echo " "; \
            echo "***"; \
            echo "  No /usr/sbin/dkms or /usr/bin/rpmbuild, don't know how to make kernel module."; \
            echo "***"; \
            echo " "; \
            exit 6; \
        fi

	@echo " "
	@echo "***"
	@echo "  'make kernelmodule' ok."
	@echo "***"
	@echo " "

pythonmodule:
	@python setup.py build

install_kernelmodule: kernelmodule
	@echo " "
	@echo "***"
	@echo "  Installing kernel module."
	@echo "***"
	@if ([ ! -z $(DKMS) ] && [ -x $(DKMS) ]); then \
            $(DKMS) install -m utun -v $(KMODVER); \
            depmod -a; \
        elif ([ -x /usr/bin/rpmbuild ] && [ ! -f $(DKMS) ]); then \
            rpm_installed=`/bin/rpm -qa kmod-utun`; \
            if test -n "$$rpm_installed"; then \
                echo "Removing existing kmod-utun module."; \
                /bin/rpm -e kmod-utun; \
            fi; \
            /bin/rpm -ih `find ./utun-rpm/RPMS -name "*\.rpm"`; \
            /bin/rpm -ih `find ./utun-rpm/SRPMS -name "*\.rpm"`; \
        else \
            echo " "; \
            echo "***"; \
            echo "  No /usr/sbin/dkms or /usr/bin/rpmbuild, don't know how to install kernel module."; \
            echo "***"; \
            echo " "; \
            exit 7; \
        fi

	@echo " "
	@echo "***"
	@echo "  Please change your configuration to load utun kernel module"
	@echo "  upon system startup."
	@echo "***"


install_pythonmodule: pythonmodule
	@echo "Installing python modules"
	@if [ /bin/true ]; then \
            python_result=`$(PY_EXEC) setup.py install --prefix=$(PREFIX) >ddtb-install.log; echo $$?`; \
            if [ $$python_result -ne 0 ]; then \
                cat ddtb-install.log; \
                echo " "; \
                echo " "; \
                echo "***"; \
                echo " "; \
                echo " Warning: install_python_module (python setup.py) return code is $$python_result."; \
                echo " If you are running python 2.7 or newer, this can be caused by md.py install and"; \
                echo " there is no cause for concern."; \
                echo " "; \
                echo " If you are running python 2.6 or earlier, you may need to fix your distutils.cfg"; \
                echo " and altinstall.pth (see http://packages.python.org/distribute/easy_install.html#custom-installation-locations )."; \
                echo " "; \
                echo "***"; \
                echo " "; \
            fi; \
            echo " "; \
            echo "***"; \
            echo "  See ddtb-install.log for details."; \
            echo "***"; \
            echo " "; \
        fi

install: test_prereq install_pythonmodule install_kernelmodule
	@echo ""
	@echo "Installing scripts to $(PREFIX)/sbin/"
	@install -m 0755 -d $(PREFIX)/sbin

	@for f in src/bin/*; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/; \
        done

	@echo ""
	@echo "Installing management scripts under $(PREFIX)/sbin/ddtbmanage/"
	@install -m 0755 -d $(PREFIX)/sbin/ddtbmanage
	@install -m 0755 -d $(PREFIX)/sbin/ddtbmanage/ddtbmanage
	@install -m 0755 -d $(PREFIX)/sbin/ddtbmanage/hashstore
	@install -m 0755 -d $(PREFIX)/sbin/ddtbmanage/templates
	@install -m 0755 -d $(PREFIX)/sbin/ddtbmanage/static

	@for f in src/management/tbmanage.py src/management/README.hashstore; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/ddtbmanage; \
        done

	@for f in src/management/ddtbmanage/*; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/ddtbmanage/ddtbmanage; \
        done

	@for f in src/management/hashstore/*; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/ddtbmanage/hashstore; \
        done

	@for f in src/management/templates/*; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/ddtbmanage/templates; \
        done

	@for f in src/management/static/*; do \
            echo "  $$f"; install -m 755 $$f $(PREFIX)/sbin/ddtbmanage/static; \
        done

	@if [ -x /usr/bin/id ]; then \
            user_exists=$(shell id ddtb >/dev/null 2>&1; echo $$?); \
            if [ $$user_exists -ne 0 ]; then \
                useradd -U -M -c "ddtb user" -r ddtb; \
            fi; \
        fi

	@echo " "
	@echo "*** "
	@echo "  Installing configuration files and creating log directory:"
	@echo "    /etc/ddtb"
	@install -o root -g ddtb -m 0750 -d /etc/ddtb
	@echo "    /var/log/ddtbmanage"
	@install -o root -g ddtb -m 0775 -d /var/log/ddtbmanage
	@echo "    /var/log/ddtb"
	@install -o root -g ddtb -m 0775 -d /var/log/ddtb

	@if [ -e /etc/redhat-release ]; then \
            install -o root -g root -m 0755 ./etc/init.d/ddtb-rh /etc/init.d/ddtb; \
            echo "    /etc/init.d/ddtb"; \
            install -o root -g root -m 0755 ./etc/init.d/ddtbmanage-rh /etc/init.d/ddtbmanage; \
            echo "    /etc/init.d/ddtbmanage"; \
            /sbin/chkconfig ddtb on >/dev/null 2>&1; \
            /sbin/chkconfig ddtbmanage on >/dev/null 2>&1; \
        elif [ -e /etc/debian_version ]; then \
                install -o root -g root -m 0755 ./etc/init.d/ddtb-debian /etc/init.d/ddtb; \
                echo "    /etc/init.d/ddtb"; \
                install -o root -g root -m 0755 ./etc/init.d/ddtbmanage-debian /etc/init.d/ddtbmanage; \
                echo "    /etc/init.d/ddtbmanage"; \
                /usr/sbin/update-rc.d ddtb defaults >/dev/null 2>&1; \
                /usr/sbin/update-rc.d ddtbmanage defaults >/dev/null 2>&1; \
        else \
            echo "***"; \
            echo " "; \
            echo " "; \
            echo "***"; \
            echo "  No debian_version or redhat_release in /etc, don't know this distro."; \
            echo "  Installation aborted."; \
            echo "***"; \
            echo " "; \
            exit 8; \
        fi

	@for f in etc/ddtb/*; do \
            if [ "X$$apikey" = "X" ]; then \
                db_pass="/"; \
                check_again=1; \
                while [ $$check_again -eq 1 ]; do \
                    case $$db_pass in \
                       */* ) db_pass=`dd if=/dev/urandom bs=1 count=8 2>/dev/null | base64`;; \
                       * ) check_again=0;; \
                    esac; \
                done; \
                apikey=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64`; \
                db_key=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64`; \
                scookie=`dd if=/dev/urandom bs=1 count=48 2>/dev/null | base64`; \
                hskey=`dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64`; \
            fi; \
            filename=`basename $$f`; \
            curtime=`date +%Y%m%d-%H%M%S`; \
            if [ ! -e /etc/ddtb/$$filename ]; then \
                echo "    /etc/ddtb/$$filename"; \
                install -o root -g ddtb -m 0640 ./etc/ddtb/$$filename /etc/ddtb/; \
                sed -i 's%PLACEHOLDER_DDTB_DB_PASSWORD%'"$$db_pass"'%' /etc/ddtb/$$filename; \
                sed -i 's%PLACEHOLDER_APIKEY%'"$$apikey"'%' /etc/ddtb/$$filename; \
                sed -i 's%PLACEHOLDER_DB_KEY%'"$$db_key"'%' /etc/ddtb/$$filename; \
                sed -i 's%PLACEHOLDER_SECURECOOKIE%'"$$scookie"'%' /etc/ddtb/$$filename; \
                sed -i 's%PLACEHOLDER_HASHSTOREKEY%'"$$hskey"'%' /etc/ddtb/$$filename; \
            else \
                echo " "; \
                echo "  PREVIOUS config file /etc/ddtb/$$filename exists, not overwriting."; \
                echo "  Creating file with name $$filename-$$curtime instead."; \
                echo " "; \
                echo "    /etc/ddtb/$$filename-$$curtime"; \
                install -o root -g ddtb -m 0640 ./etc/ddtb/$$filename /etc/ddtb/$$filename-$$curtime; \
                sed -i 's%PLACEHOLDER_DDTB_DB_PASSWORD%'"$$db_pass"'%' /etc/ddtb/$$filename-$$curtime; \
                sed -i 's%PLACEHOLDER_APIKEY%'"$$apikey"'%' /etc/ddtb/$$filename-$$curtime; \
                sed -i 's%PLACEHOLDER_DB_KEY%'"$$db_key"'%' /etc/ddtb/$$filename-$$curtime; \
                sed -i 's%PLACEHOLDER_SECURECOOKIE%'"$$scookie"'%' /etc/ddtb/$$filename-$$curtime; \
                sed -i 's%PLACEHOLDER_HASHSTOREKEY%'"$$hskey"'%' /etc/ddtb/$$filename-$$curtime; \
            fi; \
        done

	@echo "***"
	@echo " "

	@echo " "
	@echo " "
	@echo "If everything went well, you should now have:"
	@echo "  - user account 'ddtb' with group 'ddtb'"
	@echo "  - file /etc/ddtb/ddtb.cfg, owned by root:ddtb, mode 0640"
	@echo "  - file /etc/ddtb/ddtbmanage.cfg, owned by root:ddtb, mode 0640"
	@echo "  - file /etc/ddtb/ddtbmanage-hashstore.cfg, owned by root:ddtb, mode 0640"
	@echo "  - directory /var/log/ddtbmanage, owned by root:ddtb, mode 0775"
	@echo "  - file /etc/init.d/ddtb, owned by root:root, mode 0755, to start the service"
	@echo " "
	@echo "  Make sure you load the utun kernel module upon system startup."
	@echo " "
	@echo "  Please go through the config files and edit them to suit your environment."
	@echo " "
	@echo "Now you need to: "
	@echo " "
	@echo "  1) Run $(PREFIX)/sbin/ddtb-create-database ."
	@echo " "
	@echo "  2) Add tunnel client accounts using $(PREFIX)/sbin/ddtb-accounts ( -h for help)."
	@echo " "
	@echo "  3) Add web-management admin account(s) using $(PREFIX)/sbin/ddtbmanage/hashstore/hashstoremanager.py ( -h for help)."
	@echo " "
	@echo "  4) Use '/etc/init.d/ddtb start' or 'service ddtb start' to start TSP broker."
	@echo " "
	@echo "  5) Use $(PREFIX)/sbin/ddtbmanage/tbmanage.py to start web management GUI."
	@echo " "
