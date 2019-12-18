// swift-tools-version:4.0
import PackageDescription


let package = Package(
    name: "FwiSecurity",
    products: [
        .library(name: "CommonCrypto", targets: ["CommonCrypto"]),
        .library(name: "FwiSecurity", targets: ["FwiSecurity"]),
    ],
    dependencies: [
        .package(url: "https://github.com/phuc0302/swift-core.git", from:"2.0.0"),
    ],
    targets: [
        .target(name: "CommonCrypto", dependencies: [], path: "CommonCrypto"),
        .target(name: "FwiSecurity", dependencies: ["FwiCore"], path: "FwiSecurity"),

        .testTarget(name: "FwiSecurity", dependencies: ["FwiCore", "CommonCrypto", "FwiSecurity"])
    ],
    swiftLanguageVersions: [3,4]
)
