import PackageDescription


let package = Package(
    name: "FwiSecurity",
    targets: [
        Target(
            name: "FwiSecurity"
        )
    ],
    dependencies: [
        .Package(url: "https://github.com/phuc0302/swift-core.git", majorVersion: 1),
    ]
)
