import XCTest
@testable import AWSv4

let credentials = AWSCredentials(
    accessKeyId: "AXXXXXXXXXXXXXXXXXXX",
    secretAccessKey: "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
)

let url = URL(string: "https://s3.us-east-1.amazonaws.com/")!

let date = Date(timeIntervalSince1970: 1677601246)

final class AWSv4Tests: XCTestCase {
    func testSignedURL() throws {
        let headers = ["x-custom-header": "abcde"]
        let signer = AWSRequestSigner(credentials: credentials, service: "s3", region: "us-east-1")
        let signedURL = signer.signedURL(url: url, headers: headers, expires: 3600, date: date)
        let components = URLComponents(url: signedURL, resolvingAgainstBaseURL: false)
        let signature = components?.queryItems?.first { $0.name == "X-Amz-Signature" }
        XCTAssertEqual(signature?.value, "0a7e0e3e9521f33cec9e77846748673dfe8469e0f63dd089eaea24d4cf74a630")
    }

    func testSignedHeaders() throws {
        let headers = ["x-custom-header": "abcde"]
        let signer = AWSRequestSigner(credentials: credentials, service: "s3", region: "us-east-1")
        let signedHeaders = signer.signedHeaders(url: url, headers: headers, date: date)
        let authorization = signedHeaders["authorization"]
        XCTAssertEqual(authorization, "AWS4-HMAC-SHA256 Credential=AXXXXXXXXXXXXXXXXXXX/20230228/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-custom-header,Signature=bcd162664a7df3a0007e6128ebe6f8c3f61bb282c7839ea28e0bd250fec79d1e")
    }
}
