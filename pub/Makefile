#####################################################################
#
# ISPWork Makefile.
#
#

PROC=32
CUSR=root

install:
	#
	# Patch rc file with current user settings.
	#
	cp ispwork.rc ispwork.rc.install 
	sed -i 's|%%USER%%|${CUSR}|' ispwork.rc.install
	sed -i 's|%%HOME%%|${HOME}|' ispwork.rc.install
	sed -i 's|%%PROC%%|${PROC}|' ispwork.rc.install
	#
	# Create runtime directories.
	#
	install -m 777 -d ${HOME}/log
	install -m 777 -d ${HOME}/run
	#
	# Install file in init.d
	#
	sudo install -m 755 ispwork.rc.install /etc/init.d/ispwork
	sudo update-rc.d ispwork defaults
	#
	# Remove temp
	#
	rm -f ispwork.rc.install
	