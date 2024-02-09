use std::collections::HashMap;

use chrono::Utc;
use oauth2::TokenResponse;
use serde::Deserialize;

use crate::{
    requests::{GenerateAccessTokenRequest, GenerateAccessTokenResponse},
    AccessToken,
};

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct AuthorizedUserCredentials {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) quota_project_id: Option<String>,
    pub(crate) refresh_token: String,
    pub(crate) universe_domain: String, // auth_uri?
                                        // token_uri?
}

impl AuthorizedUserCredentials {
    async fn access_token(&self) -> Result<AccessToken, reqwest::Error> {
        self.access_token_with_scopes(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
    }

    async fn access_token_with_scopes(
        &self,
        scopes: &[&str],
    ) -> Result<AccessToken, reqwest::Error> {
        let oauth = oauth2::basic::BasicClient::new(
            oauth2::ClientId::new(self.client_id.clone()),
            Some(oauth2::ClientSecret::new(self.client_secret.clone())),
            oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_owned()).unwrap(),
            Some(
                oauth2::TokenUrl::new("https://accounts.google.com/o/oauth2/token".to_owned())
                    .unwrap(),
            ),
        );

        let result = oauth
            .exchange_refresh_token(&oauth2::RefreshToken::new(self.refresh_token.clone()))
            .add_scopes(
                scopes
                    .into_iter()
                    .map(|scope| oauth2::Scope::new(scope.to_string())),
            )
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .unwrap();

        Ok(AccessToken {
            access_token: result.access_token().secret().to_owned(),
            refresh_token: None,
            expiry_time: Utc::now(),
        })
    }
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
pub(crate) enum SourceCredentials {
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

impl SourceCredentials {
    pub(crate) async fn access_token(&self) -> Result<AccessToken, reqwest::Error> {
        match self {
            SourceCredentials::AuthorizedUser(u) => u.access_token().await,
            SourceCredentials::ServiceAccount(_) => todo!(),
            SourceCredentials::ExternalAccount(_) => todo!(),
            SourceCredentials::ExternalAccountAuthorizedUser(_) => todo!(),
            SourceCredentials::GdchServiceAccount(_) => todo!(),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub(crate) enum Credentials {
    #[serde(rename = "impersonated_service_account")]
    ImpersonatedServiceAccount(ImpersonatedServiceAccountCredentials),
    #[serde(untagged)]
    SourceCredentials(SourceCredentials),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ImpersonatedServiceAccountCredentials {
    delegates: Vec<String>,
    service_account_impersonation_url: String,
    source_credentials: SourceCredentials,
    // universe_domain: Option<String>, TODO: is this ever set?
}

impl ImpersonatedServiceAccountCredentials {
    pub(crate) async fn access_token(&self) -> Result<AccessToken, reqwest::Error> {
        self.access_token_with_scopes(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
    }

    pub(crate) async fn access_token_with_scopes(
        &self,
        scopes: &[&str],
    ) -> Result<AccessToken, reqwest::Error> {
        // Use cloud-platform scope, need to access IAM Service Account Credentials API.
        let underlying = self.source_credentials.access_token().await?;

        let delegates = self
            .delegates
            .iter()
            .map(|d| d.as_ref())
            .collect::<Vec<_>>();
        let client = reqwest::Client::new();
        let scope = scopes.into_iter().map(|s| s.as_ref()).collect::<Vec<_>>();

        let body = GenerateAccessTokenRequest {
            delegates,
            scope,
            lifetime: None,
        };

        let request = client
            .post(&self.service_account_impersonation_url)
            .bearer_auth(underlying.access_token)
            .json(&body)
            .build()?;

        let response = client.execute(request).await?;

        response.error_for_status_ref()?;

        let payload = response.json::<GenerateAccessTokenResponse>().await?;

        Ok(AccessToken {
            access_token: payload.access_token,
            refresh_token: None,
            expiry_time: payload.expire_time,
        })
    }
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
