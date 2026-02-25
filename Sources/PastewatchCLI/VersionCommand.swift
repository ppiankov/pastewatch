import ArgumentParser

struct Version: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Print version information"
    )

    func run() {
        print("pastewatch-cli 0.7.0")
    }
}
