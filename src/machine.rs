use std::{
    borrow::Cow,
    env,
    net::{IpAddr, Ipv4Addr},
};

use reqwest::{
    header::{HeaderMap, HeaderValue},
    StatusCode,
};
use tokio::{fs::File, io::AsyncReadExt as _, net::lookup_host, select, sync::OnceCell};

const METADATA_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";
const METADATA_DEFAULT_DNS: &str = "metadata.google.internal.";
const USER_AGENT: &str = "google-adc-client-rust/0.1.0";

#[derive(Debug)]
pub struct MetadataServer {
    client: reqwest::Client,
    host: String,
    on_gce: OnceCell<bool>,
    project_id: OnceCell<String>,
    numeric_project_id: OnceCell<String>,
    instance_id: OnceCell<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum MetadataRequestError {
    #[error("Error when making HTTP request")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Etag was not valid visible ASCII characters")]
    EtagNotAscii,
    #[error("Server responded with a status code that was not successful")]
    NotSuccessful(StatusCode),
    #[error("Server responded with not found")]
    NotFound,
}

pub struct MetadataResponse {
    pub data: String,
    pub etag: Option<String>,
}

impl MetadataServer {
    pub fn new() -> Self {
        let mut default_headers = HeaderMap::with_capacity(1);
        default_headers.insert("metadata-flavor", HeaderValue::from_static("Google"));

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .user_agent(USER_AGENT)
            .build()
            .unwrap();

        MetadataServer {
            client,
            host: std::env::var(METADATA_HOST_ENV).unwrap_or(METADATA_DEFAULT_DNS.to_string()),
            on_gce: OnceCell::default(),
            project_id: OnceCell::default(),
            numeric_project_id: OnceCell::default(),
            instance_id: OnceCell::default(),
        }
    }

    pub async fn project_id(&self) -> Result<&str, MetadataRequestError> {
        self.project_id
            .get_or_try_init(|| self.get("project/project-id"))
            .await
            .map(|x| x.as_str().trim())
    }

    pub async fn numeric_project_id(&self) -> Result<&str, MetadataRequestError> {
        self.numeric_project_id
            .get_or_try_init(|| self.get("project/numeric-project-id"))
            .await
            .map(|x| x.as_str().trim())
    }

    pub async fn instance_id(&self) -> Result<&str, MetadataRequestError> {
        self.instance_id
            .get_or_try_init(|| self.get("instance/id"))
            .await
            .map(|x| x.as_str().trim())
    }

    pub async fn internal_ip(&self) -> Result<String, MetadataRequestError> {
        self.get("instance/network-interfaces/0/ip")
            .await
            .map(|x| x.trim().to_owned())
    }

    pub async fn email(
        &self,
        service_account: Option<impl AsRef<str>>,
    ) -> Result<String, MetadataRequestError> {
        let path = match service_account {
            Some(sa) => Cow::Owned(format!("instance/service-accounts/{}/email", sa.as_ref())),
            None => Cow::Borrowed("instance/service-accounts/default/email"),
        };

        self.get(path).await.map(|x| x.trim().to_owned())
    }

    pub async fn external_ip(&self) -> Result<String, MetadataRequestError> {
        self.get("instance/network-interfaces/0/access-configs/0/external-ip")
            .await
            .map(|x| x.trim().to_owned())
    }

    pub async fn hostname(&self) -> Result<String, MetadataRequestError> {
        self.get("instance/hostname")
            .await
            .map(|x| x.trim().to_owned())
    }

    pub async fn get(&self, suffix: impl AsRef<str>) -> Result<String, MetadataRequestError> {
        self.get_etag(suffix).await.map(|response| response.data)
    }

    pub async fn get_etag(
        &self,
        suffix: impl AsRef<str>,
    ) -> Result<MetadataResponse, MetadataRequestError> {
        let suffix = suffix.as_ref().trim_start_matches('/');
        let url = format!("http://{}/computeMetadata/v1/{}", self.host, suffix);

        // TODO: add retry
        let result = self
            .client
            .get(url)
            .header("metadata-flavor", "Google")
            .send()
            .await?;

        if result.status() == StatusCode::NOT_FOUND {
            return Err(MetadataRequestError::NotFound);
        }

        if !result.status().is_success() {
            return Err(MetadataRequestError::NotSuccessful(result.status()));
        }

        let etag_header = result.headers().get("etag");
        let etag = etag_header.and_then(|hv| hv.to_str().ok().map(|v| v.to_owned()));

        let data = result.text().await?;

        Ok(MetadataResponse { data, etag })
    }

    pub async fn on_gce(&self) -> bool {
        if std::env::var(METADATA_HOST_ENV).map_or(false, |env| !env.is_empty()) {
            return true;
        }

        self.on_gce
            .get_or_init(|| async {
                // TODO: do "try harder" tests
                select! {
                    res = self.connect_to_metadata_server() => res,
                    res = self.lookup_metadata_server_dns() => res
                }
            })
            .await
            .to_owned()
    }

    async fn connect_to_metadata_server(&self) -> bool {
        let url = format!("http://{}", METADATA_IP.to_canonical());
        let result = self.client.get(url).send().await;

        result.map_or(false, |res| {
            res.headers()
                .get("metadata-flavor")
                .map_or(false, |v| v == "Google")
        })
    }

    async fn lookup_metadata_server_dns(&self) -> bool {
        lookup_host(METADATA_DEFAULT_DNS)
            .await
            .map_or(false, |mut res| res.any(|v| v.ip() == METADATA_IP))
    }

    async fn system_may_be_gce(&self) -> bool {
        if env::consts::OS != "linux" {
            return false;
        }

        if let Ok(mut f) = File::open("/sys/class/dmi/id/product_name").await {
            let mut contents = vec![];
            let _ = f.read_to_end(&mut contents).await;
            let str = String::from_utf8_lossy(&contents);
            let trimmed_str = str.trim();
            trimmed_str == "Google" || trimmed_str == "Google Compute Engine"
        } else {
            false
        }
    }
}
