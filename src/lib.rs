mod credentials;
mod machine;
mod requests;

use std::{ffi::OsString, fs::File, io::BufReader, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use credentials::{
    Credentials, ImpersonatedServiceAccountCredentials, ServiceAccountCredentials,
    SourceCredentials,
};
use machine::MetadataServer;

enum TokenState {
    Invalid,
    Stale,
    Fresh,
}

pub struct AccessToken {
    access_token: String,
    refresh_token: Option<String>,
    expiry_time: DateTime<Utc>,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"ya29.********")
            .field("expiry_time", &self.expiry_time)
            .finish()
    }
}

impl AccessToken {
    // TODO: this should be possible to make const in chrono 0.5
    fn refresh_threshold() -> Duration {
        Duration::minutes(3) + Duration::seconds(45)
    }

    fn token_state_with_early_expiry(&self, early_expiry: Duration) -> TokenState {
        let time_to_expiry = self.expiry_time.signed_duration_since(Utc::now());

        if time_to_expiry <= early_expiry {
            TokenState::Invalid
        } else if time_to_expiry <= Self::refresh_threshold() {
            TokenState::Stale
        } else {
            TokenState::Fresh
        }
    }

    fn token_state(&self) -> TokenState {
        self.token_state_with_early_expiry(Duration::zero())
    }

    pub fn as_str(&self) -> &str {
        &self.access_token
    }

    pub fn expiry_time(&self) -> &DateTime<Utc> {
        &self.expiry_time
    }
}

#[derive(Debug)]
pub struct ApplicationDefaultCredentials {
    pub(crate) credentials: CredentialsSource,
    pub quota_project_id: Option<String>,
    pub use_client_certificate: bool,
}

#[derive(Debug)]
pub(crate) enum CredentialsSource {
    File(Credentials),
    MetadataServer(MetadataServer),
}

impl ApplicationDefaultCredentials {
    pub fn builder() -> ApplicationDefaultCredentialsBuilder {
        ApplicationDefaultCredentialsBuilder::new()
    }

    pub async fn new() -> Result<Self, String> {
        ApplicationDefaultCredentialsBuilder::new().build().await
    }
}

pub struct AccessTokenWithScopesSource<'a> {
    source: AccessTokenWithScopesSourceEnum<'a>,
}

pub(crate) enum AccessTokenWithScopesSourceEnum<'a> {
    ImpersonatedServiceAccount(&'a ImpersonatedServiceAccountCredentials),
    ServiceAccount(&'a ServiceAccountCredentials),
}

impl<'a> AccessTokenWithScopesSource<'a> {
    pub async fn access_token_with_scopes(
        &self,
        scopes: &[&str],
    ) -> Result<AccessToken, reqwest::Error> {
        match &self.source {
            AccessTokenWithScopesSourceEnum::ImpersonatedServiceAccount(isa) => {
                isa.access_token_with_scopes(scopes).await
            }
            AccessTokenWithScopesSourceEnum::ServiceAccount(_sa) => todo!(), //sa.access_token().await,
        }
    }
}

// AIP-4110
impl ApplicationDefaultCredentials {
    pub async fn access_token(&self) -> Result<AccessToken, reqwest::Error> {
        match &self.credentials {
            CredentialsSource::File(Credentials::ImpersonatedServiceAccount(isa)) => {
                isa.access_token().await
            }
            CredentialsSource::File(Credentials::SourceCredentials(source_credentials)) => {
                source_credentials.access_token().await
            }
            CredentialsSource::MetadataServer(ms) => ms.access_token().await,
        }
    }

    pub async fn access_token_with_scopes_source(&self) -> Option<AccessTokenWithScopesSource<'_>> {
        match &self.credentials {
            CredentialsSource::File(Credentials::ImpersonatedServiceAccount(isa)) => {
                Some(AccessTokenWithScopesSource {
                    source: AccessTokenWithScopesSourceEnum::ImpersonatedServiceAccount(isa),
                })
            }
            CredentialsSource::File(Credentials::SourceCredentials(
                SourceCredentials::ServiceAccount(sa),
            )) => Some(AccessTokenWithScopesSource {
                source: AccessTokenWithScopesSourceEnum::ServiceAccount(sa),
            }),
            _ => None,
        }
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

    #[tokio::test]
    async fn get_token() {
        let adc = ApplicationDefaultCredentials::builder()
            .build()
            .await
            .unwrap();
        insta::assert_debug_snapshot!(adc.access_token().await)
    }
}
