import XCTest
@testable import AWSv4

let credentials = Credentials(
    accessKeyId: "AXXXXXXXXXXXXXXXXXXX",
    secretAccessKey: "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
)

let url = URL(string: "https://lambda.us-east-1.api.aws/2023-01-01/Execute")!

final class AWSv4Tests: XCTestCase {
    func testExample() throws {
        let headers = ["content-type": "application/json"]
        let signer = RequestSigner(credentials: credentials, service: "s3", region: "us-east-1")
        let signedURL = signer.signedURL(url: url, headers: headers, expires: 3600)
        let signedHeaders = signer.signedHeaders(url: url, headers: headers)
        print(signedURL)
        print(signedHeaders)
    }
}
