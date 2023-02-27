// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "AWSv4",
    platforms: [
        .macOS(.v12),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v9),
        .driverKit(.v22),
        .macCatalyst(.v13)
    ],
    products: [
        .library(name: "AWSv4", targets: ["AWSv4"]),
    ],
    dependencies: [
         .package(url: "https://github.com/swift-cloud/Compute", from: "2.13.0"),
    ],
    targets: [
        .target(name: "AWSv4", dependencies: ["Compute"]),
        .testTarget(name: "AWSv4Tests", dependencies: ["AWSv4"]),
    ]
)
