use reqwest;
use tokio;
use serde_json;
use serde_derive;

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    #[serde(rename = "Modified")]
    pub modified: String,
    #[serde(rename = "Published")]
    pub published: String,
    pub access: Access,
    pub assigner: String,
    #[serde(default)]
    pub capec: Vec<Capec>,
    pub cvss: Option<f64>,
    #[serde(rename = "cvss-time")]
    pub cvss_time: Option<String>,
    #[serde(rename = "cvss-vector")]
    pub cvss_vector: Option<String>,
    pub cwe: String,
    pub id: String,
    pub impact: Impact,
    #[serde(rename = "last-modified")]
    pub last_modified: String,
    pub references: Vec<String>,
    pub summary: String,
    #[serde(rename = "vulnerable_configuration")]
    pub vulnerable_configuration: Vec<String>,
    #[serde(rename = "vulnerable_configuration_cpe_2_2")]
    pub vulnerable_configuration_cpe22: Vec<::serde_json::Value>,
    #[serde(rename = "vulnerable_product")]
    pub vulnerable_product: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub authentication: Option<String>,
    pub complexity: Option<String>,
    pub vector: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capec {
    pub id: String,
    pub name: String,
    pub prerequisites: String,
    #[serde(rename = "related_weakness")]
    pub related_weakness: Vec<String>,
    pub solutions: String,
    pub summary: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
    pub availability: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
}

#[tokio::main]
async fn main() {
    let body = reqwest::get("https://cve.circl.lu/api/last")
        .await.unwrap()
        .text()
        .await.unwrap();

    let cves: Vec<Cve> = serde_json::from_str(&body).unwrap();

    for cve in cves {
        println!("{}", cve.summary);
    }
}
