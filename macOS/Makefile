all:
	dotnet build
	./bin/Debug/net9.0-macos/osx-*/StackTracer.app/Contents/MacOS/StackTracer

symbolicate-txt:
	DEVELOPER_DIR=$(shell xcode-select -p) $(shell xcode-select -p)/../SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash -v $(TMPDIR)/crash.txt

symbolicate-sh:
	chmod +x $(TMPDIR)/crash.sh
	$(TMPDIR)/crash.sh
