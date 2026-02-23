import ArgumentParser
import Foundation
import PastewatchCore

struct Explain: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show detection type details"
    )

    @Argument(help: "Type name to explain (omit to list all)")
    var typeName: String?

    func run() throws {
        if let name = typeName {
            guard let type = SensitiveDataType.allCases.first(where: {
                $0.rawValue.lowercased() == name.lowercased()
            }) else {
                FileHandle.standardError.write(Data("error: unknown type '\(name)'\n".utf8))
                FileHandle.standardError.write(Data("available types: \(SensitiveDataType.allCases.map { $0.rawValue }.joined(separator: ", "))\n".utf8))
                throw ExitCode(rawValue: 2)
            }
            printDetail(type)
        } else {
            printAll()
        }
    }

    private func printAll() {
        for type in SensitiveDataType.allCases {
            print("\(type.rawValue) [\(type.severity.rawValue)]: \(type.explanation)")
        }
    }

    private func printDetail(_ type: SensitiveDataType) {
        print("Type:     \(type.rawValue)")
        print("Severity: \(type.severity.rawValue)")
        print("About:    \(type.explanation)")
        print("Examples:")
        for example in type.examples {
            print("  \(example)")
        }
    }
}
