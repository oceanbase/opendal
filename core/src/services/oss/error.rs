// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use bytes::Buf;
use http::Response;
use http::StatusCode;
use quick_xml::de;
use serde::Deserialize;

use crate::raw::*;
use crate::*;

/// OssError is the error returned by oss service.
#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct OssError {
    code: String,
    message: String,
    request_id: String,
    host_id: String,
}

/// Parse error response into Error.
pub(super) fn parse_error(resp: Response<Buffer>) -> Error {
    let (parts, mut body) = resp.into_parts();
    let bs = body.copy_to_bytes(body.remaining());

    let (mut kind, mut retryable) = match parts.status {
        StatusCode::NOT_FOUND => (ErrorKind::NotFound, false),
        StatusCode::FORBIDDEN => (ErrorKind::PermissionDenied, false),
        StatusCode::PRECONDITION_FAILED | StatusCode::NOT_MODIFIED | StatusCode::CONFLICT => {
            (ErrorKind::ConditionNotMatch, false)
        }
        StatusCode::INTERNAL_SERVER_ERROR
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => (ErrorKind::Unexpected, true),
        _ => (ErrorKind::Unexpected, false),
    };

    let (message, oss_err) = match de::from_reader::<_, OssError>(bs.clone().reader()) {
        Ok(oss_err) => (format!("{oss_err:?}"), Some(oss_err)),
        Err(_) => (String::from_utf8_lossy(&bs).into_owned(), None),
    };

    if let Some(oss_err) = oss_err {
        (kind, retryable) = parse_oss_error_code(oss_err.code.as_str(), oss_err.message.as_str()).unwrap_or((kind, retryable));
    }

    let mut err = Error::new(kind, message);

    err = with_error_response_context(err, parts);

    if retryable {
        err = err.set_temporary();
    }

    err
}

pub fn parse_oss_error_code(code: &str, msg: &str) -> Option<(ErrorKind, bool)> {
    if msg.contains("invalid argument") {
        return Some((ErrorKind::ConfigInvalid, false))
    }
    match code {
        "NoSuchBucket" => Some((ErrorKind::InvalidObjectStorageEndpoint, false)),
        "BucketNameInvalidError" => Some((ErrorKind::InvalidObjectStorageEndpoint, false)),
        "InvalidDigest" => Some((ErrorKind::ChecksumError, false)),
        "InvalidBucketName" => Some((ErrorKind::InvalidObjectStorageEndpoint, false)), 
        "InvalidObjectName" => Some((ErrorKind::ConfigInvalid, false)),
        "InvalidArgument" => Some((ErrorKind::ConfigInvalid, false)),
        "PositionNotEqualToLength" => Some((ErrorKind::PwriteOffsetNotMatch, false)),
        "QpsLimitExceeded" => Some((ErrorKind::RateLimited, true)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Error response example is from https://www.alibabacloud.com/help/en/object-storage-service/latest/error-responses
    #[test]
    fn test_parse_error() {
        let bs = bytes::Bytes::from(
            r#"
<?xml version="1.0" ?>
<Error xmlns="http://doc.oss-cn-hangzhou.aliyuncs.com">
    <Code>
        AccessDenied
    </Code>
    <Message>
        Query-string authentication requires the Signature, Expires and OSSAccessKeyId parameters
    </Message>
    <RequestId>
        1D842BC54255****
    </RequestId>
    <HostId>
        oss-cn-hangzhou.aliyuncs.com
    </HostId>
</Error>
"#,
        );

        let out: OssError = de::from_reader(bs.reader()).expect("must success");
        println!("{out:?}");

        assert_eq!(out.code, "AccessDenied");
        assert_eq!(out.message, "Query-string authentication requires the Signature, Expires and OSSAccessKeyId parameters");
        assert_eq!(out.request_id, "1D842BC54255****");
        assert_eq!(out.host_id, "oss-cn-hangzhou.aliyuncs.com");
    }
}
