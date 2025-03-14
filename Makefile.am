SUBDIRS = src

cppcheck:
	@cppcheck \
		--inline-suppr \
		--enable=warning,style,performance,portability \
		--inconclusive --check-level=exhaustive \
		--template="warning: {file},{line},{severity},{id},{message}" \
		-I . -I src -I src/engines/ -I src/engines/ftwcoraza -I src/engines/ftwdummy -I src/engines/ftwmodsecurity \
		--error-exitcode=1 \
		--language=c \
		--force \
		--verbose .

check-static: cppcheck
