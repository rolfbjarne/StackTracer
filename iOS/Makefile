DEVICE?=Rolf's iPhone 15

all:
	dotnet build /p:RuntimeIdentifier=ios-arm64
	xcrun devicectl device install app --device "$(DEVICE)" ./bin/Debug/net9.0-ios/ios-arm64/StackTracer.app
	xcrun devicectl device process launch --device "$(DEVICE)" --console com.companyname.StackTracer
	xcrun devicectl device copy from --device "$(DEVICE)" --source /tmp/crash.txt --destination crash.txt --domain-type appDataContainer --domain-identifier com.companyname.StackTracer
	xcrun devicectl device copy from --device "$(DEVICE)" --source /tmp/crash.sh --destination crash.sh --domain-type appDataContainer --domain-identifier com.companyname.StackTracer

symbolicate-txt:
	DEVELOPER_DIR=$(shell xcode-select -p) $(shell xcode-select -p)/../SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash -v ./crash.txt

symbolicate-sh:
	chmod +x crash.sh
	./crash.sh

