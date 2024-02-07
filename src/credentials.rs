use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct AuthorizedUserCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub quota_project_id: Option<String>,
    pub refresh_token: String,
    pub universe_domain: String, // auth_uri?
                                 // token_uri?
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ServiceAccountCredentials {
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
    pub universe_domain: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ExternalAccountCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub subject_token_type: String,
    pub service_account_impersonation_url: Option<String>,
    pub token_url: String,
    pub credential_source: CredentialSource,
    pub token_info_url: String,
    pub service_account_impersonation: String, // TODO: this is a type
    pub quota_project_id: String,
    pub workforce_pool_user_project: String,
    pub universe_domain: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ExternalAccountAuthorizedUserCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    pub refresh_token: String,
    pub token_url: String,
    pub token_info_url: String,
    pub revoke_url: String,
    pub quota_project_id: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct GdchServiceAccountCredentials {
    pub format_version: String,
    pub project: String,
    pub name: String,
    pub ca_cert_path: String,
    pub private_key_id: String,
    pub private_key: String,
    pub token_uri: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum SourceCredentials {
    #[serde(rename = "authorized_user")]
    AuthorizedUser(AuthorizedUserCredentials),
    #[serde(rename = "service_account")]
    ServiceAccount(ServiceAccountCredentials),
    #[serde(rename = "external_account")]
    ExternalAccount(ExternalAccountCredentials),
    #[serde(rename = "external_account_authorized_user")]
    ExternalAccountAuthorizedUser(ExternalAccountAuthorizedUserCredentials),
    #[serde(rename = "gdch_service_account")]
    GdchServiceAccount(GdchServiceAccountCredentials),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Credentials {
    #[serde(rename = "impersonated_service_account")]
    ImpersonatedServiceAccount {
        delegates: Vec<String>,
        service_account_impersonation_url: String,
        source_credentials: SourceCredentials,
        // universe_domain: Option<String>, TODO: is this ever set?
    },
    #[serde(untagged)]
    SourceCredentials(SourceCredentials),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum CredentialSource {
    Aws {
        environment_id: String,
        region_url: Option<String>,
        url: Option<String>,
        regional_cred_verification_url: String,
        imdsv2_session_token_url: Option<String>,
    },
    Azure {
        url: String,
        headers: Option<HashMap<String, String>>,
        format: CredentialSourceFormat,
    },
    File {
        file: String,
        format: CredentialSourceFormat,
    },
    Executable {
        executable: ExecutableDetails,
    },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum CredentialSourceFormat {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "json")]
    Json { subject_token_field_name: String },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ExecutableDetails {
    pub command: String,
    pub timeout_millis: Option<u32>,
    pub output_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::ApplicationDefaultCredentials;

    #[tokio::test]
    async fn test_user_adc() {
        insta::assert_debug_snapshot!(ApplicationDefaultCredentials::builder()
            .with_application_credentials(format!(
                "{}/src/user_application_default_credentials.json",
                std::env::var("CARGO_MANIFEST_DIR").unwrap()
            ))
            .build()
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_impersonated_adc() {
        insta::assert_debug_snapshot!(ApplicationDefaultCredentials::builder()
            .with_application_credentials(format!(
                "{}/src/impersonated_application_default_credentials.json",
                std::env::var("CARGO_MANIFEST_DIR").unwrap()
            ))
            .build()
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_sa_with_key_adc() {
        insta::assert_debug_snapshot!(ApplicationDefaultCredentials::builder()
            .with_application_credentials(format!(
                "{}/src/sa_with_key.json",
                std::env::var("CARGO_MANIFEST_DIR").unwrap()
            ))
            .build()
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_aws_with_key_adc() {
        insta::assert_debug_snapshot!(ApplicationDefaultCredentials::builder()
            .with_application_credentials(format!(
                "{}/src/aws.json",
                std::env::var("CARGO_MANIFEST_DIR").unwrap()
            ))
            .build()
            .await
            .unwrap());
    }
}
