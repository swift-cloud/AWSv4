//
//  RequestSigner.swift
//
//
//  Modified by Andrew Barba on 2/27/23.
//
//  Created by Soto Project:
//  https://github.com/soto-project/soto-core/blob/main/Sources/SotoSignerV4/signer.swift
//

import Compute

/// Amazon Web Services V4 Signer
public struct RequestSigner: Sendable {
    /// Security credentials for accessing AWS services
    public let credentials: Credentials
    /// Service signing name. In general this is the same as the service name
    public let service: String
    /// AWS region you are working in
    public let region: String

    static let hashedEmptyBody = Crypto.sha256([]).toHexString()

    /// Initialise the Signer class with AWS credentials
    public init(credentials: Credentials, service: String, region: String) {
        self.credentials = credentials
        self.service = service
        self.region = region
    }

    /// Enum for holding request payload
    public enum BodyData {
        /// String
        case string(String)
        /// Data
        case data(Data)
        /// SwiftNIO ByteBuffer
        case byteBuffer([UInt8])
        /// Don't use body when signing request
        case unsignedPayload
        /// Internally used when S3 streamed payloads
        case s3chunked
    }

    /// Process URL before signing
    ///
    /// `signURL` and `signHeaders` make assumptions about the URLs they are provided, this function cleans up a URL so it is ready
    /// to be signed by either of these functions. It sorts the query params and ensures they are properly percent encoded
    public func processURL(url: URL) -> URL? {
        guard var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let urlQueryString = urlComponents.queryItems?
            .sorted {
                if $0.name < $1.name { return true }
                if $0.name > $1.name { return false }
                guard let value1 = $0.value, let value2 = $1.value else { return false }
                return value1 < value2
            }
            .map { item in item.value.map { "\(item.name)=\($0.uriEncode())" } ?? "\(item.name)=" }
            .joined(separator: "&")
        urlComponents.percentEncodedQuery = urlQueryString
        // S3 requires "+" encoded in the URL
        if service == "s3" {
            urlComponents.percentEncodedPath = urlComponents.path.s3PathEncode()
        }
        return urlComponents.url
    }

    /// Generate signed headers, for a HTTP request
    /// - Parameters:
    ///   - url: Request URL
    ///   - method: Request HTTP method
    ///   - headers: Request headers
    ///   - body: Request body
    ///   - omitSecurityToken: Should we include security token in the query parameters
    ///   - date: Date that URL is valid from, defaults to now
    /// - Returns: Request headers with added "authorization" header that contains request signature
    public func signHeaders(
        url: URL,
        method: HTTPMethod = .get,
        headers: HTTPHeaders = [:],
        body: BodyData? = nil,
        omitSecurityToken: Bool = false,
        date: Date = Date()
    ) -> HTTPHeaders {
        let bodyHash = RequestSigner.hashedPayload(body)
        let dateString = RequestSigner.timestamp(date)
        var headers = headers
        // add date, host, sha256 and if available security token headers
        headers["host"] = Self.hostname(from: url)
        headers["x-amz-date"] = dateString
        headers["x-amz-content-sha256"] = bodyHash
        if !omitSecurityToken, let sessionToken = credentials.sessionToken {
            headers["x-amz-security-token"] = sessionToken
        }
        // construct signing data. Do this after adding the headers as it uses data from the headers
        let signingData = RequestSigner.SigningData(url: url, method: method, headers: headers, body: body, bodyHash: bodyHash, date: dateString, signer: self)

        // construct authorization string
        let authorization = "AWS4-HMAC-SHA256 " +
        "Credential=\(credentials.accessKeyId)/\(signingData.date)/\(region)/\(service)/aws4_request," +
        "SignedHeaders=\(signingData.signedHeaders)," +
        "Signature=\(signature(signingData: signingData))"

        // add Authorization header
        headers["authorization"] = authorization
        // now we have signed the request we can add the security token if required
        if omitSecurityToken, let sessionToken = credentials.sessionToken {
            headers["x-amz-security-token"] = sessionToken
        }

        return headers
    }

    /// Generate a signed URL, for a HTTP request
    /// - Parameters:
    ///   - url: Request URL
    ///   - method: Request HTTP method
    ///   - headers: Request headers
    ///   - body: Request body
    ///   - expires: How long before the signed URL expires
    ///   - omitSecurityToken: Should we include security token in the query parameters
    ///   - date: Date that URL is valid from, defaults to now
    /// - Returns: Signed URL
    public func signURL(
        url: URL,
        method: HTTPMethod = .get,
        headers: HTTPHeaders = [:],
        body: BodyData? = nil,
        expires: TimeInterval,
        omitSecurityToken: Bool = false,
        date: Date = Date()
    ) -> URL {
        var headers = headers
        headers["host"] = Self.hostname(from: url)
        // Create signing data
        var signingData = RequestSigner.SigningData(url: url, method: method, headers: headers, body: body, date: RequestSigner.timestamp(date), signer: self)
        // Construct query string. Start with original query strings and append all the signing info.
        var query = url.query ?? ""
        if query.count > 0 {
            query += "&"
        }
        query += "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        query += "&X-Amz-Credential=\(credentials.accessKeyId)/\(signingData.date)/\(region)/\(service)/aws4_request"
        query += "&X-Amz-Date=\(signingData.datetime)"
        query += "&X-Amz-Expires=\(Int(expires))"
        query += "&X-Amz-SignedHeaders=\(signingData.signedHeaders)"
        if !omitSecurityToken, let sessionToken = credentials.sessionToken {
            query += "&X-Amz-Security-Token=\(sessionToken.uriEncode())"
        }
        // Split the string and sort to ensure the order of query strings is the same as AWS
        query = query.split(separator: "&")
            .sorted()
            .joined(separator: "&")
            .queryEncode()

        // update unsignedURL in the signingData so when the canonical request is constructed it includes all the signing query items
        signingData.unsignedURL = URL(string: url.absoluteString.split(separator: "?")[0] + "?" + query)! // NEED TO DEAL WITH SITUATION WHERE THIS FAILS
        query += "&X-Amz-Signature=\(signature(signingData: signingData))"
        if omitSecurityToken, let sessionToken = credentials.sessionToken {
            query += "&X-Amz-Security-Token=\(sessionToken.uriEncode())"
        }

        // Add signature to query items and build a new Request
        let signedURL = URL(string: url.absoluteString.split(separator: "?")[0] + "?" + query)!

        return signedURL
    }

    /// Temporary structure passed from calls to `startSigningChunks` and
    /// subsequent calls to `signChunk`
    public struct ChunkedSigningData {
        /// signature for streamed data
        public let signature: String
        let datetime: String
        let signingKey: Data
    }

    /// Start the process of signing a s3 chunked upload.
    ///
    /// Update headers and generate first signature. See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
    /// for more details
    /// - Parameters:
    ///   - url: url
    ///   - method: http method
    ///   - headers: original headers
    ///   - date: date to use for signing
    /// - Returns: Tuple of updated headers and signing data to use in first call to `signChunk`
    public func startSigningChunks(url: URL, method: HTTPMethod = .get, headers: HTTPHeaders = [:], date: Date = Date()) -> (headers: HTTPHeaders, signingData: ChunkedSigningData) {
        let bodyHash = RequestSigner.hashedPayload(.s3chunked)
        let dateString = RequestSigner.timestamp(date)
        var headers = headers
        // add date, host, sha256 and if available security token headers
        headers["host"] = Self.hostname(from: url)
        headers["x-amz-date"] = dateString
        headers["x-amz-content-sha256"] = bodyHash
        if let sessionToken = credentials.sessionToken {
            headers["x-amz-security-token"] = sessionToken
        }
        // remove content-length header
        headers["content-length"] = nil

        // construct signing data. Do this after adding the headers as it uses data from the headers
        let signingData = RequestSigner.SigningData(url: url, method: method, headers: headers, bodyHash: bodyHash, date: dateString, signer: self)
        let signingKey = self.signingKey(date: signingData.date)
        let signature = self.signature(signingData: signingData)
        let chunkedSigningData = ChunkedSigningData(signature: signature, datetime: signingData.datetime, signingKey: signingKey)

        // construct authorization string
        let authorization = "AWS4-HMAC-SHA256 " +
        "Credential=\(credentials.accessKeyId)/\(signingData.date)/\(region)/\(service)/aws4_request," +
        "SignedHeaders=\(signingData.signedHeaders)," +
        "Signature=\(signature)"

        // add Authorization header
        headers["authorization"] = authorization

        return (headers: headers, signingData: chunkedSigningData)
    }

    /// Generate the signature for a chunk in a s3 chunked upload
    /// - Parameters:
    ///   - body: Body of chunk
    ///   - signingData: Signing data returned from previous `signChunk` or `startSigningChunk` if this is the first call
    /// - Returns: signing data that includes the signature and other data that is required for signing the next chunk
    public func signChunk(body: BodyData, signingData: ChunkedSigningData) -> ChunkedSigningData {
        let stringToSign = self.chunkStringToSign(body: body, previousSignature: signingData.signature, datetime: signingData.datetime)
        let signature = Crypto.Auth.code(for: Data(stringToSign.utf8), secret: signingData.signingKey, using: .sha256).toHexString()
        return ChunkedSigningData(signature: signature, datetime: signingData.datetime, signingKey: signingData.signingKey)
    }

    /// structure used to store data used throughout the signing process
    struct SigningData {
        let url: URL
        let method: HTTPMethod
        let hashedPayload: String
        let datetime: String
        let headersToSign: HTTPHeaders
        let signedHeaders: String
        var unsignedURL: URL

        var date: String { return String(datetime.prefix(8)) }

        init(url: URL, method: HTTPMethod = .get, headers: HTTPHeaders = HTTPHeaders(), body: BodyData? = nil, bodyHash: String? = nil, date: String, signer: RequestSigner) {
            self.url = url
            self.method = method
            self.datetime = date
            self.unsignedURL = self.url

            if let hash = bodyHash {
                self.hashedPayload = hash
            } else if signer.service == "s3" {
                self.hashedPayload = "UNSIGNED-PAYLOAD"
            } else {
                self.hashedPayload = RequestSigner.hashedPayload(body)
            }

            let headersNotToSign: Set<String> = [
                "authorization",
                "content-length",
                "content-type",
                "expect",
                "user-agent",
            ]
            var headersToSign: HTTPHeaders = [:]
            var signedHeadersArray: [String] = []
            for header in headers {
                let lowercasedHeaderName = header.key.lowercased()
                if headersNotToSign.contains(lowercasedHeaderName) {
                    continue
                }
                headersToSign[lowercasedHeaderName] = header.value
                signedHeadersArray.append(lowercasedHeaderName)
            }
            self.headersToSign = headersToSign
            self.signedHeaders = signedHeadersArray.sorted().joined(separator: ";")
        }
    }

    // Stage 3 Calculating signature as in https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    func signature(signingData: SigningData) -> String {
        let signingKey = self.signingKey(date: signingData.date)
        let kSignature = Crypto.Auth.code(for: Data(stringToSign(signingData: signingData).utf8), secret: signingKey, using: .sha256)
        return kSignature.toHexString()
    }

    /// Stage 2 Create the string to sign as in https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    func stringToSign(signingData: SigningData) -> String {
        let stringToSign = "AWS4-HMAC-SHA256\n" +
        "\(signingData.datetime)\n" +
        "\(signingData.date)/\(region)/\(service)/aws4_request\n" +
        Crypto.sha256(canonicalRequest(signingData: signingData)).toHexString()
        return stringToSign
    }

    /// Stage 1 Create the canonical request as in https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    func canonicalRequest(signingData: SigningData) -> String {
        let canonicalHeaders = signingData.headersToSign
            .map { (key: $0.key.lowercased(), value: $0.value) }
            .sorted { $0.key < $1.key }
            .map { return "\($0.key):\($0.value.trimmingCharacters(in: CharacterSet.whitespaces).removeSequentialWhitespace())" }
            .joined(separator: "\n")
        let canonicalPath: String
        let urlComps = URLComponents(url: signingData.unsignedURL, resolvingAgainstBaseURL: false)!
        if service == "s3" {
            canonicalPath = urlComps.path.uriEncodeWithSlash()
        } else {
            // non S3 paths need to be encoded twice
            canonicalPath = urlComps.percentEncodedPath.uriEncodeWithSlash()
        }
        let canonicalRequest = "\(signingData.method.rawValue)\n" +
        "\(canonicalPath)\n" +
        "\(signingData.unsignedURL.query ?? "")\n" + // assuming query parameters have are already percent encoded correctly
        "\(canonicalHeaders)\n\n" +
        "\(signingData.signedHeaders)\n" +
        signingData.hashedPayload
        return canonicalRequest
    }

    /// get signing key
    func signingKey(date: String) -> Data {
        let kDate = Crypto.Auth.code(for: date, secret: "AWS4\(credentials.secretAccessKey)", using: .sha256)
        let kRegion = Crypto.Auth.code(for: Data(region.utf8), secret: kDate, using: .sha256)
        let kService = Crypto.Auth.code(for: Data(service.utf8), secret: kRegion, using: .sha256)
        let kSigning = Crypto.Auth.code(for: Data("aws4_request".utf8), secret: kService, using: .sha256)
        return kSigning
    }

    /// chunked upload string to sign
    func chunkStringToSign(body: BodyData, previousSignature: String, datetime: String) -> String {
        let date = String(datetime.prefix(8))
        let stringToSign = "AWS4-HMAC-SHA256-PAYLOAD\n" +
        "\(datetime)\n" +
        "\(date)/\(region)/\(service)/aws4_request\n" +
        "\(previousSignature)\n" +
        "\(Self.hashedEmptyBody)\n" +
        Self.hashedPayload(body)
        return stringToSign
    }

    /// Create a SHA256 hash of the Requests body
    static func hashedPayload(_ payload: BodyData?) -> String {
        guard let payload = payload else { return hashedEmptyBody }
        let hash: String?
        switch payload {
        case .string(let string):
            hash = Crypto.sha256(string).toHexString()
        case .data(let data):
            hash = Crypto.sha256(data).toHexString()
        case .byteBuffer(let byteBuffer):
            hash = Crypto.sha256(byteBuffer).toHexString()
        case .unsignedPayload:
            return "UNSIGNED-PAYLOAD"
        case .s3chunked:
            return "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        }
        if let hash = hash {
            return hash
        } else {
            return hashedEmptyBody
        }
    }

    /// return a timestamp formatted for signing requests
    /// yyyyMMdd'T'HHmmss'Z'
    static func timestamp(_ date: Date) -> String {
        let c = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let year = String(format: "%04d", c.year!)
        let month = String(format: "%02d", c.month!)
        let day = String(format: "%02d", c.day!)
        let hour = String(format: "%02d", c.hour!)
        let minute = String(format: "%02d", c.minute!)
        let second = String(format: "%02d", c.second!)
        return "\(year)\(month)\(day)T\(hour)\(minute)\(second)Z"
    }

    /// returns port from URL. If port is set to 80 on an http url or 443 on an https url nil is returned
    private static func port(from url: URL) -> Int? {
        guard let port = url.port else { return nil }
        guard url.scheme != "http" || port != 80 else { return nil }
        guard url.scheme != "https" || port != 443 else { return nil }
        return port
    }

    private static func hostname(from url: URL) -> String {
        "\(url.host ?? "")\(port(from: url).map { ":\($0)" } ?? "")"
    }
}

extension String {
    func queryEncode() -> String {
        return addingPercentEncoding(withAllowedCharacters: String.queryAllowedCharacters) ?? self
    }

    func s3PathEncode() -> String {
        return addingPercentEncoding(withAllowedCharacters: String.s3PathAllowedCharacters) ?? self
    }

    func uriEncode() -> String {
        return addingPercentEncoding(withAllowedCharacters: String.uriAllowedCharacters) ?? self
    }

    func uriEncodeWithSlash() -> String {
        return addingPercentEncoding(withAllowedCharacters: String.uriAllowedWithSlashCharacters) ?? self
    }

    static let s3PathAllowedCharacters = CharacterSet.urlPathAllowed.subtracting(.init(charactersIn: "+@()&$=:,'!*"))
    static let uriAllowedWithSlashCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")
    static let uriAllowedCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    static let queryAllowedCharacters = CharacterSet(charactersIn: "/;+").inverted
}

public extension URL {
    /// return URL path, but do not remove the slash at the end if it exists.
    ///
    /// There doesn't seem to be anyway to do this without parsing the path myself
    /// If I could guarantee macOS 10.11 then I could use `hasDirectoryPath`.
    var pathWithSlash: String {
        let relativeString = self.relativeString
        let doesPathEndInSlash: Bool
        // does path end in "/"
        if let questionMark = relativeString.firstIndex(of: "?") {
            let prevCharacter = relativeString.index(before: questionMark)
            doesPathEndInSlash = (relativeString[prevCharacter] == "/")
        } else if let hashCharacter = relativeString.firstIndex(of: "#") {
            let prevCharacter = relativeString.index(before: hashCharacter)
            doesPathEndInSlash = (relativeString[prevCharacter] == "/")
        } else {
            let prevCharacter = relativeString.index(before: relativeString.endIndex)
            doesPathEndInSlash = (relativeString[prevCharacter] == "/")
        }
        var path = self.path
        if doesPathEndInSlash, path != "/" {
            path += "/"
        }
        return path
    }
}

private extension String {
    func removeSequentialWhitespace() -> String {
        return reduce(into: "") { result, character in
            if result.last?.isWhitespace != true || character.isWhitespace == false {
                result.append(character)
            }
        }
    }
}
