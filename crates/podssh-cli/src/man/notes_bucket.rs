//! The notes of the bucket carrier (T-725): `--carrier s3:FILE`, a bucket of
//! the S3 API between a node and its client, and the file that FILE is.

/// The note of `podssh node NAME TARGET --carrier s3:FILE`.
pub(super) const NODE: &str = "--carrier s3:FILE carries the node's stream through a bucket of the S3 API, for a \
     host whose one way out is an object store. FILE says where the bucket is and where the keys are (see FILES). \
     Each end writes its objects under one prefix and reads the other's. So a key needs a write right on one \
     prefix and a read right on the other. Each object is sealed under a key of FILE's secret, its name a MAC \
     of it: the bucket holds no byte in clear. The node waits until a client's hello comes, then serves that \
     one stream. Each request goes on one connection, through HTTPS_PROXY, one at a time. The road is slow: \
     each end polls each 2 to 3 s, and each request is billed at most providers. podssh names no provider; \
     the endpoint is yours.";

/// FILE in FILES.
pub(super) fn file() -> (Vec<String>, String) {
    (
        vec!["the file of --carrier s3:FILE".to_string()],
        "The bucket of the carrier: NAME = VALUE lines; a line that starts with # is a comment. endpoint, \
         https://HOST[:PORT][/PATH] of the S3 API; region, us-east-1 unless given; bucket; style, path or \
         virtual. up and down, the prefixes of the client's way and the node's, the same at both ends. \
         credentials, a file of the AWS form \
         (aws_access_key_id, aws_secret_access_key, aws_session_token) for both ways. Or write-credentials and \
         read-credentials, two key pairs; read-credentials none reads a public prefix unsigned. secret-file, at \
         least 16 bytes that both ends hold. A relative path is read beside FILE. No key goes in FILE itself; \
         a name that is no setting is refused (78), in words that never hold a key."
            .to_string(),
    )
}
