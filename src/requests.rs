use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer};

fn serialize_duration<S>(v: &Option<Duration>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match *v {
        Some(ref duration) => s.serialize_some(&format!(
            "{}.{}s",
            duration.num_seconds(),
            duration.subsec_nanos()
        )),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GenerateAccessTokenRequest<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<&'a str>,
    pub scope: Vec<&'a str>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_duration"
    )]
    pub lifetime: Option<Duration>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAccessTokenResponse {
    pub access_token: String,
    pub expire_time: DateTime<Utc>,
}
