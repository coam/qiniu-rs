extern crate ring;
extern crate data_encoding;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use ring::hmac;
use data_encoding::BASE64URL;

pub struct Config {
    pub access_key: String,
    pub secret_key: String,
}

impl Config {
    pub fn new<S: Into<String>>(access_key: S, secret_key: S) -> Config {
        Config {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseBodyForAppClient {
    pub name: String,
    pub size: String,
    pub w: String,
    pub h: String,
    pub hash: String,
}

// [Field attributes](https://serde.rs/field-attrs.html)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PutPolicy {
    pub scope: String,
    // Bucket
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_prefixal_scope: Option<i32>,
    // IsPrefixalScope
    pub deadline: u32,
    // UnixTimestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_only: Option<i32>,
    // AllowFileUpdating
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_user: Option<String>,
    // EndUserId
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    // RedirectURL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_body: Option<String>,
    //pub return_body: Option<ResponseBodyForAppClient>,
    // ResponseBodyForAppClient
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    // RequestUrlForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_host: Option<String>,
    // RequestHostForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_body: Option<String>,
    // RequestBodyForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_body_type: Option<String>,
    // RequestBodyTypeForAppServer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_ops: Option<String>,
    // PersistentOpsCmds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_notify_url: Option<String>,
    // PersistentNotifyUrl
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_pipeline: Option<String>,
    // PersistentPipeline
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save_key: Option<String>,
    // SaveKey
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fsize_min: Option<i64>,
    // FileSizeMin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fsize_limit: Option<i64>,
    // FileSizeLimit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_mime: Option<i32>,
    // AutoDetectMimeType
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_limit: Option<String>,
    // MimeLimit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<i32>,                   // FileType
}

impl PutPolicy {
    pub fn new<S: Into<String>>(scope: S, deadline: u32, response_body: String) -> PutPolicy {
        PutPolicy {
            scope: scope.into(),
            is_prefixal_scope: None,
            deadline: deadline,
            insert_only: None,
            end_user: None,
            return_url: None,
            return_body: Some(response_body),
            callback_url: None,
            callback_host: None,
            callback_body: None,
            callback_body_type: None,
            persistent_ops: None,
            persistent_notify_url: None,
            persistent_pipeline: None,
            save_key: None,
            fsize_min: None,
            fsize_limit: None,
            detect_mime: None,
            mime_limit: None,
            file_type: None,
        }
    }

    // EncodedEntryURI
    pub fn urlsafe_base64_encode(origin_str: String) -> String {
        //let ssss = serde_json::to_vec(&self).unwrap();
        //let pkey_s = String::from_utf8_lossy(&ssss);
        //println!("==============>{:?}", pkey_s);

        BASE64URL.encode(origin_str.as_str().as_bytes())
    }

    pub fn to_base64(&self) -> String {
        //let ssss = serde_json::to_vec(&self).unwrap();
        //let pkey_s = String::from_utf8_lossy(&ssss);
        //println!("==============>{:?}", pkey_s);

        BASE64URL.encode(&serde_json::to_vec(&self).unwrap())
    }

    pub fn generate_uptoken(&self, config: &Config) -> String {
        // [0.16.9]
        //let sign_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, config.secret_key.as_bytes());
        // [0.13.5]
        let sign_key = hmac::SigningKey::new(&ring::digest::SHA1, config.secret_key.as_bytes());

        //println!("sign_key---------------->sign_key: {:?}", sign_key.to_string());

        let self_base64 = self.to_base64();
        println!("self_base64---------------->self_base64: {:?}", self_base64);

        let signature = hmac::sign(&sign_key, self_base64.as_bytes());
        println!("signature---------------->signature: {:?}", signature);

        //let ss = hash(MessageDigest::sha1(), self_base64.as_bytes());
        //println!("ss---------------->ss: {:?}", ss);

        let signature_base64 = data_encoding::BASE64URL.encode(signature.as_ref());
        println!("signature_base64---------------->signature_base64: {:?}", signature_base64);

        format!(
            "{}:{}:{}",
            config.access_key,
            signature_base64,
            self_base64
        )
    }

    // 七牛 CDN 接口授权Token
    // [管理凭证](https://developer.qiniu.com/kodo/manual/1201/access-token)
    pub fn generate_cdn_token(&self, config: &Config, sign_uri: &str) -> String {

        // 创建签名 key
        // [0.16.9]
        //let sign_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, config.secret_key.as_bytes());
        // [0.13.5]
        let sign_key = hmac::SigningKey::new(&ring::digest::SHA1, config.secret_key.as_bytes());

        // 创建签名
        let signature = hmac::sign(&sign_key, sign_uri.as_bytes());

        // base64_encode 编码
        let signature_base64_encode = data_encoding::BASE64URL.encode(signature.as_ref());

        format!("{}:{}", config.access_key, signature_base64_encode)
    }
}


