all:
	dotnet build
	./bin/Debug/net9.0-macos/osx-arm64/StackTracer.app/Contents/MacOS/StackTracer
	$(MAKE) symbolicate

symbolicate:
	DEVELOPER_DIR=$(xcode-select -p) $(xcode-select -p)/../Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash -v /tmp/crash.txt
