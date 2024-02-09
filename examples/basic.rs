use google_adc_client::ApplicationDefaultCredentials;
use reqwest::Url;

#[tokio::main]
async fn main() {
    let auth = ApplicationDefaultCredentials::builder()
        .build()
        .await
        .unwrap();

    let token = auth.access_token().await.unwrap();

    println!("Token: {}", token.as_str());
    println!("Debug: {:?}", token);

    println!(
        "Quota project: {}",
        auth.quota_project_id.unwrap_or_default()
    );

    let client = reqwest::Client::new();

    let url = Url::parse_with_params(
        "https://www.googleapis.com/oauth2/v1/tokeninfo",
        &[("access_token", token.as_str())],
    )
    .unwrap();

    let response = client.get(url).send().await.unwrap().text().await.unwrap();

    println!("{}", response);
    //let id_token = auth.id_token("audience");

    //println!("{:?}", id_token);
}
