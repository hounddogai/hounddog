use std::collections::HashMap;

use anyhow::Result;
use reqwest::blocking::{Client as HttpClient, Request as HttpRequest};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::enums::{HoundDogEnv, Language};
use crate::sentry_err;
use crate::structs::{DataElement, DataSink, Sanitizer, ScanResults, User};

#[derive(Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
}

pub struct HoundDogCloudApi {
    http: HttpClient,
    base_url: String,
}

impl HoundDogCloudApi {
    pub fn new(env: &HoundDogEnv, api_key: &str) -> Result<Self> {
        Ok(Self {
            http: HttpClient::builder()
                .default_headers({
                    let auth_header = format!("Bearer {}", api_key);
                    let mut headers = HeaderMap::new();
                    headers.insert(AUTHORIZATION, auth_header.parse().unwrap());
                    headers.insert(ACCEPT, "application/json".parse().unwrap());
                    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
                    headers
                })
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),

            base_url: match env {
                HoundDogEnv::Dev => "http://localhost:8000".to_string(),
                HoundDogEnv::Staging => "https://api.staging.hounddog.ai".to_string(),
                HoundDogEnv::Prod => "https://api.hounddog.ai".to_string(),
            },
        })
    }

    fn send_request<T: DeserializeOwned>(&self, request: HttpRequest) -> Result<T> {
        match self.http.execute(request) {
            Ok(response) => {
                if response.status().is_success() {
                    let response_text = response.text()?;
                    let response_json: T = serde_json::from_str(&response_text)?;
                    Ok(response_json)
                } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                    Err(sentry_err!("Unauthorized. Please check your HOUNDDOG_API_KEY."))
                } else {
                    Err(sentry_err!(
                        "HoundDog Cloud returned an error: {}",
                        response.text().unwrap_or_default()
                    ))
                }
            }
            Err(e) => Err(sentry_err!("Failed to connect to HoundDog Cloud: {e}")),
        }
    }

    pub fn authenticate(&self) -> Result<User> {
        let request = self.http.get(format!("{}/users/current/", self.base_url)).build()?;
        let user = self.send_request(request)?;

        Ok(user)
    }

    pub fn get_data_elements(&self) -> Result<HashMap<String, DataElement>> {
        let request = self.http.get(format!("{}/data-elements/", self.base_url)).build()?;
        let data_elements: PaginatedResponse<DataElement> = self.send_request(request)?;
        Ok(data_elements
            .items
            .into_iter()
            .map(|data_element| (data_element.id.clone(), data_element))
            .collect())
    }

    pub fn get_data_sinks(&self) -> Result<HashMap<Language, HashMap<String, DataSink>>> {
        let request = self.http.get(format!("{}/data-sinks/", self.base_url)).build()?;
        let data_sinks: PaginatedResponse<DataSink> = self.send_request(request)?;
        Ok(data_sinks.items.into_iter().fold(HashMap::new(), |mut map, data_sink| {
            map.entry(data_sink.language)
                .or_default()
                .insert(data_sink.id.clone(), data_sink);
            map
        }))
    }

    pub fn get_sanitizers(&self) -> Result<Vec<Sanitizer>> {
        let request = self.http.get(format!("{}/sanitizers/", self.base_url)).build()?;
        let sanitizers: PaginatedResponse<Sanitizer> = self.send_request(request)?;
        Ok(sanitizers.items)
    }

    pub fn upload_scan_results(&self, scan_results: &ScanResults) -> Result<()> {
        let request = self
            .http
            .post(format!("{}/scan-results/", self.base_url))
            .body(serde_json::to_string(scan_results)?)
            .build()?;
        self.send_request(request)?;
        Ok(())
    }
}
