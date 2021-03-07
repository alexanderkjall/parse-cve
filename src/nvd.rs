use crate::error;
use flate2::bufread::GzDecoder;
use std::io::{Read, Write};

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    #[serde(rename = "CVE_data_type")]
    pub cve_data_type: String,
    #[serde(rename = "CVE_data_format")]
    pub cve_data_format: String,
    #[serde(rename = "CVE_data_version")]
    pub cve_data_version: String,
    #[serde(rename = "CVE_data_numberOfCVEs")]
    pub cve_data_number_of_cves: String,
    #[serde(rename = "CVE_data_timestamp")]
    pub cve_data_timestamp: String,
    #[serde(rename = "CVE_Items")]
    pub cve_items: Vec<CveItem>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveItem {
    pub cve: Cve,
    pub configurations: Configurations,
    pub impact: Impact,
    pub published_date: String,
    pub last_modified_date: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    #[serde(rename = "data_type")]
    pub data_type: String,
    #[serde(rename = "data_format")]
    pub data_format: String,
    #[serde(rename = "data_version")]
    pub data_version: String,
    #[serde(rename = "CVE_data_meta")]
    pub cve_data_meta: CveDataMeta,
    pub problemtype: Problemtype,
    pub references: References,
    pub description: Description2,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveDataMeta {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "ASSIGNER")]
    pub assigner: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problemtype {
    #[serde(rename = "problemtype_data")]
    pub problemtype_data: Vec<ProblemtypeDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemtypeDaum {
    pub description: Vec<Description>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct References {
    #[serde(rename = "reference_data")]
    pub reference_data: Vec<ReferenceDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceDaum {
    pub url: String,
    pub name: String,
    pub refsource: String,
    pub tags: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description2 {
    #[serde(rename = "description_data")]
    pub description_data: Vec<DescriptionDaum>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DescriptionDaum {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configurations {
    #[serde(rename = "CVE_data_version")]
    pub cve_data_version: String,
    pub nodes: Vec<Node>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub operator: String,
    pub children: Option<Vec<Children>>,
    #[serde(rename = "cpe_match")]
    #[serde(default)]
    pub cpe_match: Vec<CpeMatch2>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Children {
    pub operator: String,
    #[serde(rename = "cpe_match")]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub cpe23_uri: String,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
    pub version_start_including: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch2 {
    pub vulnerable: bool,
    pub cpe23_uri: String,
    pub version_end_excluding: Option<String>,
    pub version_start_including: Option<String>,
    pub version_end_including: Option<String>,
    pub version_start_excluding: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
    pub base_metric_v3: Option<BaseMetricV3>,
    pub base_metric_v2: Option<BaseMetricV2>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseMetricV3 {
    pub cvss_v3: CvssV3,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3 {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseMetricV2 {
    pub cvss_v2: CvssV2,
    pub severity: String,
    pub exploitability_score: f64,
    pub impact_score: f64,
    pub ac_insuf_info: Option<bool>,
    pub obtain_all_privilege: Option<bool>,
    pub obtain_user_privilege: Option<bool>,
    pub obtain_other_privilege: Option<bool>,
    pub user_interaction_required: Option<bool>,
}

#[derive(Default, Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2 {
    pub version: String,
    pub vector_string: String,
    pub access_vector: String,
    pub access_complexity: String,
    pub authentication: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
}

pub fn download(year: u16) -> error::Result<Root> {
    let cache_dir = std::path::PathBuf::from("/tmp/parse-cve-cache");

    if !cache_dir.exists() {
        std::fs::create_dir(&cache_dir)?;
    }

    let filename = cache_dir.join(year.to_string());

    if !filename.exists() {
        let dl = reqwest::blocking::get(&format!("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz", year))?.bytes()?;

        let mut f = std::fs::File::create(&filename)?;
        f.write_all(dl.as_ref())?;
    }

    let body = std::fs::read(&filename)?;

    let mut d = GzDecoder::new(body.as_ref());
    let mut body = String::new();
    d.read_to_string(&mut body)?;
    let root: Root = serde_json::from_str(&body)?;

    Ok(root)
}