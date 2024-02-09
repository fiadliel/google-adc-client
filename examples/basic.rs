use google_adc_client::ApplicationDefaultCredentials;

#[tokio::main]
async fn main() {
    let auth = ApplicationDefaultCredentials::builder()
        .build()
        .await
        .unwrap();

    let token = auth.access_token().await.unwrap();

    println!("Token: {}", token.as_str());

    println!(
        "Quota project: {}",
        auth.quota_project_id.unwrap_or_default()
    );

    //let id_token = auth.id_token("audience");

    //println!("{:?}", id_token);
}
