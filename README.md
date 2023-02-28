# AWSv4

An AWS V4 request signing library compatible with all Apple Platforms, Swift Cloud and Fastly Compute@Edge.

```swift
let signer = RequestSigner(
    accessKeyId: "abcde",
    secretAccessKey: "12345",
    service: "s3", 
    region: "us-east-1"
)

let signedHeaders = signer.signedHeaders(
    url: .init(string: "https://s3.us-east-1.amazonaws.com/"),
    method: .get
)
```
