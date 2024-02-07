pub mod credentials;
pub mod machine;

use std::{borrow::Cow, ffi::OsString, fs::File, io::BufReader, str::FromStr, time::Duration};

use credentials::{Credentials, SourceCredentials};
use machine::MetadataServer;
use oauth2::TokenResponse;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

#[derive(Debug)]
pub struct Token {
    access_token: String,
    refresh_token: Option<String>,
    expiry: Instant,
}

enum TokenState {
    Invalid,
    Stale,
    Fresh,
}

impl Token {
    const REFRESH_THRESHOLD: Duration = Duration::from_secs(60 * 3 + 45);

    fn token_state_with_early_expiry(&self, early_expiry: Duration) -> TokenState {
        let time_to_expiry = Instant::now().duration_since(self.expiry);

        if time_to_expiry <= early_expiry {
            TokenState::Invalid
        } else if time_to_expiry <= Self::REFRESH_THRESHOLD {
            TokenState::Stale
        } else {
            TokenState::Fresh
        }
    }

    fn token_state(&self) -> TokenState {
        self.token_state_with_early_expiry(Duration::ZERO)
    }
}

#[derive(Debug)]
pub struct ApplicationDefaultCredentials {
    pub credentials: CredentialsSource,
    pub quota_project_id: Option<String>,
    pub use_client_certificate: bool,
}

#[derive(Debug)]
pub enum CredentialsSource {
    File(Credentials),
    MetadataServer(MetadataServer),
}

impl ApplicationDefaultCredentials {
    pub fn builder() -> ApplicationDefaultCredentialsBuilder {
        ApplicationDefaultCredentialsBuilder::new()
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GenerateAccessTokenRequest<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    delegates: Vec<&'a str>,
    scope: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime: Option<u32>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: String, // TODO: change to timestamp
}

// AIP-4110
impl ApplicationDefaultCredentials {
    pub async fn access_token(&self) -> String {
        self.access_token_with_scopes(&[] as &[&str]).await
    }

    pub async fn access_token_with_scopes(&self, scopes: &[impl AsRef<str>]) -> String {
        match &self.credentials {
            CredentialsSource::File(Credentials::ImpersonatedServiceAccount {
                delegates,
                service_account_impersonation_url,
                source_credentials,
            }) => {
                let underlying = self
                    .access_token_from_source_credentials(&[] as &[&str], source_credentials)
                    .await;

                let delegates = delegates
                    .into_iter()
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
                    .post(service_account_impersonation_url)
                    .bearer_auth(underlying)
                    .json(&body)
                    .build()
                    .unwrap();

                client
                    .execute(request)
                    .await
                    .unwrap()
                    .json::<GenerateAccessTokenResponse>()
                    .await
                    .unwrap()
                    .access_token
            }
            CredentialsSource::File(Credentials::SourceCredentials(creds)) => {
                self.access_token_from_source_credentials(scopes, &creds)
                    .await
            }
            CredentialsSource::MetadataServer(server) => self
                .access_token_from_metadata_server(None, scopes, server)
                .await
                .unwrap(),
        }
    }

    async fn access_token_from_source_credentials(
        &self,
        scopes: &[impl AsRef<str>],
        credentials: &SourceCredentials,
    ) -> String {
        match credentials {
            SourceCredentials::AuthorizedUser(user_credentials) => {
                let oauth = oauth2::basic::BasicClient::new(
                    oauth2::ClientId::new(user_credentials.client_id.clone()),
                    Some(oauth2::ClientSecret::new(
                        user_credentials.client_secret.clone(),
                    )),
                    oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_owned())
                        .unwrap(),
                    Some(
                        oauth2::TokenUrl::new(
                            "https://accounts.google.com/o/oauth2/token".to_owned(),
                        )
                        .unwrap(),
                    ),
                );

                oauth
                    .exchange_refresh_token(&oauth2::RefreshToken::new(
                        user_credentials.refresh_token.clone(),
                    ))
                    .add_scopes(
                        scopes
                            .into_iter()
                            .map(|scope| oauth2::Scope::new(scope.as_ref().to_string())),
                    )
                    .request_async(oauth2::reqwest::async_http_client)
                    .await
                    .unwrap()
                    .access_token()
                    .secret()
                    .to_string()
            }
            SourceCredentials::ServiceAccount(_) => todo!(),
            SourceCredentials::ExternalAccount(_) => todo!(),
            SourceCredentials::ExternalAccountAuthorizedUser(_) => todo!(),
            SourceCredentials::GdchServiceAccount(_) => todo!(),
        }
    }

    async fn access_token_from_metadata_server(
        &self,
        account: Option<&str>,
        scopes: &[impl AsRef<str>],
        metadata_server: &MetadataServer,
    ) -> Result<String, String> {
        let qs = if scopes.is_empty() {
            Cow::Borrowed("")
        } else {
            let scopes_value = scopes
                .into_iter()
                .map(|s| s.as_ref())
                .collect::<Vec<_>>()
                .join(",");

            Cow::Owned(format!("?scopes={}", urlencoding::encode(&scopes_value)))
        };

        let suffix = match account {
            Some(acc) => format!("instance/service-accounts/{acc}/token{qs}"),
            None => format!("instance/service-accounts/default/token{qs}"),
        };

        metadata_server
            .get(suffix)
            .await
            .map_err(|_| "Error getting access token".to_string())
    }

    pub fn id_token(_audience: &str) -> String {
        String::from("IdToken")
    }

    fn from_application_default_credentials(
        builder: &ApplicationDefaultCredentialsBuilder,
    ) -> Result<Self, String> {
        let f = File::open(&builder.application_credentials)
            .map_err(|_| format!("{:?}", builder.application_credentials))?;
        let reader = BufReader::new(f);
        let credentials = CredentialsSource::File(
            serde_json::from_reader(reader).map_err(|err| format!("{:?}", err))?,
        );

        Ok(ApplicationDefaultCredentials {
            credentials,
            quota_project_id: builder.quota_project_id.to_owned(),
            use_client_certificate: builder.use_client_certificate,
        })
    }

    fn from_metadata_server(
        builder: &ApplicationDefaultCredentialsBuilder,
        metadata_server: MetadataServer,
    ) -> Result<Self, String> {
        Ok(ApplicationDefaultCredentials {
            credentials: CredentialsSource::MetadataServer(metadata_server),
            quota_project_id: builder.quota_project_id.to_owned(),
            use_client_certificate: builder.use_client_certificate,
        })
    }

    // AIP-4113
    pub(crate) async fn from_builder(
        builder: ApplicationDefaultCredentialsBuilder,
    ) -> Result<Self, String> {
        match Self::from_application_default_credentials(&builder) {
            Ok(adc) => return Ok(adc),
            Err(err) => {
                let metadata_server = MetadataServer::new();

                if metadata_server.on_gce().await {
                    Self::from_metadata_server(&builder, metadata_server)
                        .map_err(|_| "Bad metadata server".to_string())
                } else {
                    Err(err)
                }
            }
        }
    }
}

pub struct ApplicationDefaultCredentialsBuilder {
    application_credentials: OsString,
    quota_project_id: Option<String>,
    use_client_certificate: bool,
}

impl ApplicationDefaultCredentialsBuilder {
    pub fn with_application_credentials<A>(mut self, application_credentials: A) -> Self
    where
        A: Into<OsString>,
    {
        self.application_credentials = application_credentials.into();
        self
    }

    pub fn with_quota_project_id<A>(mut self, quota_project_id: A) -> Self
    where
        A: Into<String>,
    {
        self.quota_project_id = Some(quota_project_id.into());
        self
    }

    pub fn with_use_client_certificate<A>(mut self, use_client_certificate: A) -> Self
    where
        A: Into<bool>,
    {
        self.use_client_certificate = use_client_certificate.into();
        self
    }

    #[cfg(unix)]
    fn default_path() -> OsString {
        let mut path = home::home_dir().expect("Could not discover user HOME directory");
        path.push(".config");
        path.push("gcloud");
        path.push("application_default_credentials.json");
        path.into_os_string()
    }

    #[cfg(target_os = "windows")]
    fn default_path() -> OsString {
        let mut path = std::path::PathBuf::new();
        path.push(std::env::var_os("APPDATA").expect("%APPDATA% must be set"));
        path.push("gcloud");
        path.push("application_default_credentials.json");
        path.into_os_string()
    }

    pub(crate) fn new() -> Self {
        Self {
            application_credentials: std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS")
                .unwrap_or(Self::default_path().into()),
            quota_project_id: std::env::var_os("GOOGLE_CLOUD_QUOTA_PROJECT").map(|s| {
                s.into_string()
                    .expect("GOOGLE_CLOUD_QUOTA_PROJECT must be valid UTF-8")
            }),
            use_client_certificate: std::env::var_os("GOOGLE_API_USE_CLIENT_CERTIFICATE").map_or(
                false,
                |s| {
                    s.into_string()
                        .ok()
                        .and_then(|s| FromStr::from_str(&s).ok())
                        .expect(
                            "GOOGLE_API_USE_CLIENT_CERTIFICATE must have value 'true' or 'false'",
                        )
                },
            ),
        }
    }

    pub async fn build(self) -> Result<ApplicationDefaultCredentials, String> {
        ApplicationDefaultCredentials::from_builder(self).await
    }
}

#[cfg(test)]
mod tests {
    use crate::ApplicationDefaultCredentials;

    // #[tokio::test]
    // async fn get_token() {
    //     let adc = ApplicationDefaultCredentials::builder().build().unwrap();
    //     insta::assert_debug_snapshot!(
    //         adc.access_token(&[
    //             "https://www.googleapis.com/auth/cloud-platform",
    //             "https://www.googleapis.com/auth/cloud-platform.read-only"
    //         ])
    //         .await
    //     )
    // }
}
