.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build debug binary
	swift build

.PHONY: release
release: ## Build release binary
	swift build -c release

.PHONY: test
test: ## Run tests
	swift test

.PHONY: run
run: build ## Build and run
	./.build/debug/pastewatch

.PHONY: clean
clean: ## Clean build artifacts
	swift package clean
	rm -rf .build release

.PHONY: lint
lint: ## Run SwiftLint
	swiftlint lint

.PHONY: fmt
fmt: ## Format code with SwiftFormat (if installed)
	@which swiftformat > /dev/null && swiftformat . || echo "swiftformat not installed"

.PHONY: app
app: release ## Build app bundle
	mkdir -p "release/Pastewatch.app/Contents/MacOS"
	mkdir -p "release/Pastewatch.app/Contents/Resources"
	cp .build/release/pastewatch "release/Pastewatch.app/Contents/MacOS/Pastewatch"
	cp Sources/Pastewatch/Resources/AppIcon.icns "release/Pastewatch.app/Contents/Resources/AppIcon.icns"
	@echo '<?xml version="1.0" encoding="UTF-8"?>' > "release/Pastewatch.app/Contents/Info.plist"
	@echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<plist version="1.0"><dict>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundleExecutable</key><string>Pastewatch</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundleIconFile</key><string>AppIcon</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundleIdentifier</key><string>com.ppiankov.pastewatch</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundleName</key><string>Pastewatch</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundlePackageType</key><string>APPL</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>CFBundleShortVersionString</key><string>0.1.0</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>LSMinimumSystemVersion</key><string>14.0</string>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>LSUIElement</key><true/>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '<key>NSHighResolutionCapable</key><true/>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo '</dict></plist>' >> "release/Pastewatch.app/Contents/Info.plist"
	@echo "App bundle created at release/Pastewatch.app"

.PHONY: dmg
dmg: app ## Build DMG installer
	hdiutil create -volname "Pastewatch" -srcfolder release/Pastewatch.app -ov -format UDZO release/Pastewatch.dmg
	@echo "DMG created at release/Pastewatch.dmg"

.PHONY: all
all: lint test release ## Run lint, tests, and build release
