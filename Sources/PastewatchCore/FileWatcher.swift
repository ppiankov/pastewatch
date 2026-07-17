import Foundation

/// Watches a directory for file changes and scans modified files.
public final class FileWatcher {
    private let directory: String
    private let config: PastewatchConfig
    private let severity: Severity?
    private let jsonOutput: Bool
    private var timer: DispatchSourceTimer?
    private var knownModDates: [String: Date] = [:]
    private let queue = DispatchQueue(label: "com.pastewatch.watcher")

    public init(directory: String, config: PastewatchConfig, severity: Severity? = nil, jsonOutput: Bool = false) {
        self.directory = (directory as NSString).standardizingPath
        self.config = config
        self.severity = severity
        self.jsonOutput = jsonOutput
    }

    /// Start watching. Blocks until stop() is called or the process is interrupted.
    public func start() {
        // Initial snapshot
        knownModDates = snapshotModDates()

        // Poll every 2 seconds for changes (portable, works on macOS + Linux)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: 2.0)
        timer.setEventHandler { [weak self] in
            self?.checkForChanges()
        }
        self.timer = timer
        timer.resume()

        // Block main thread
        dispatchMain()
    }

    /// Stop watching.
    public func stop() {
        timer?.cancel()
        timer = nil
    }

    // MARK: - Internal

    private func snapshotModDates() -> [String: Date] {
        var result: [String: Date] = [:]
        let fm = FileManager.default
        let dirURL = URL(fileURLWithPath: directory)

        guard let enumerator = fm.enumerator(
            at: dirURL,
            includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
            options: []
        ) else { return result }

        while let url = enumerator.nextObject() as? URL {
            let name = url.lastPathComponent
            if DirectoryScanner.skipDirectories.contains(name) {
                enumerator.skipDescendants()
                continue
            }
            guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .contentModificationDateKey]),
                  values.isRegularFile == true,
                  let modDate = values.contentModificationDate else { continue }

            let ext = url.pathExtension.lowercased()
            let isEnvFile = DotenvClassifier.isDotenvFile(name)
            guard isEnvFile || DirectoryScanner.allowedExtensions.contains(ext) else { continue }

            let path = url.standardizedFileURL.path
            let rel = path.hasPrefix(directory + "/")
                ? String(path.dropFirst(directory.count + 1))
                : name
            result[rel] = modDate
        }
        return result
    }

    private func checkForChanges() {
        let current = snapshotModDates()
        var changed: [String] = []

        for (path, modDate) in current {
            if let prev = knownModDates[path] {
                if modDate > prev { changed.append(path) }
            } else {
                changed.append(path) // new file
            }
        }

        knownModDates = current

        for relativePath in changed {
            scanFile(relativePath: relativePath)
        }
    }

    private func scanFile(relativePath: String) {
        let fullPath = (directory as NSString).appendingPathComponent(relativePath)
        guard let content = try? String(contentsOfFile: fullPath, encoding: .utf8),
              !content.isEmpty else { return }

        let ext = (relativePath as NSString).pathExtension.lowercased()
        let name = (relativePath as NSString).lastPathComponent
        let parsedExt = DotenvClassifier.isDotenvFile(name) ? "env" : ext

        let matchesBeforeSeverity: [DetectedMatch]
        do {
            matchesBeforeSeverity = try DirectoryScanner.scanFileContentOrThrow(
                content: content, ext: parsedExt,
                relativePath: relativePath, config: config
            )
        } catch let error as SharedSecretPatternLoadError {
            // WO-128: watch mode must surface broken shared-pattern coverage instead of reporting clean.
            let timestamp = ISO8601DateFormatter().string(from: Date())
            outputSharedPatternError(relativePath: relativePath, error: error, timestamp: timestamp)
            return
        } catch {
            return
        }

        // WO-502: watch reporting honors the same examples and allowlists as guards.
        let matches = GuardDecision.evaluate(
            matches: matchesBeforeSeverity,
            content: content,
            config: config,
            contentTrust: .trustedFile,
            minimumSeverity: severity
        ).actionableMatches

        guard !matches.isEmpty else { return }

        let timestamp = ISO8601DateFormatter().string(from: Date())

        if jsonOutput {
            outputJSON(relativePath: relativePath, matches: matches, timestamp: timestamp)
        } else {
            outputText(relativePath: relativePath, matches: matches, timestamp: timestamp)
        }
    }

    private func outputText(relativePath: String, matches: [DetectedMatch], timestamp: String) {
        for match in matches {
            let severity = match.effectiveSeverity.rawValue.uppercased()
            let line = "[\(timestamp)] \(severity) \(relativePath):\(match.line) \(match.displayName): \(match.value)"
            FileHandle.standardError.write(Data((line + "\n").utf8))
        }
    }

    private func outputJSON(relativePath: String, matches: [DetectedMatch], timestamp: String) {
        for match in matches {
            let obj: [String: Any] = [
                "timestamp": timestamp,
                "file": relativePath,
                "line": match.line,
                "type": match.displayName,
                "value": match.value,
                "severity": match.effectiveSeverity.rawValue
            ]
            if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
               let str = String(data: data, encoding: .utf8) {
                print(str)
            }
        }
    }

    private func outputSharedPatternError(
        relativePath: String,
        error: SharedSecretPatternLoadError,
        timestamp: String
    ) {
        if jsonOutput {
            let obj: [String: Any] = [
                "timestamp": timestamp,
                "file": relativePath,
                "error": "shared_pattern_load_failed",
                "message": error.localizedDescription
            ]
            if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
               let str = String(data: data, encoding: .utf8) {
                print(str)
            }
            return
        }

        let line = "[\(timestamp)] ERROR \(relativePath): shared pattern load failed: \(error.localizedDescription)"
        FileHandle.standardError.write(Data((line + "\n").utf8))
    }
}
