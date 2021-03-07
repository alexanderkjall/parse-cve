use crate::nvd;
use chrono::{NaiveDateTime, Utc, DateTime};

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

impl From<nvd::CveItem> for Cve {
    fn from(cve_item: nvd::CveItem) -> Cve {

        let cvss = match &cve_item.impact.base_metric_v3 {
            Some(metric_v3) => Some(metric_v3.cvss_v3.base_score),
            None => None,
        };

        let modified: chrono::DateTime<Utc> = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&cve_item.last_modified_date, "%Y-%m-%dT%H:%MZ").unwrap(), Utc);
        let published: chrono::DateTime<Utc> = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&cve_item.published_date, "%Y-%m-%dT%H:%MZ").unwrap(), Utc);

        let cwe = {
            if cve_item.cve.problemtype.problemtype_data.len() > 0
                && cve_item.cve.problemtype.problemtype_data[0].description.len() > 0 {
                cve_item.cve.problemtype.problemtype_data[0].description[0].value.clone()
            } else {
                "".to_string()
            }
        };

        let mut vulnerable_configuration = vec![];
        for node in cve_item.configurations.nodes {
            for m in node.cpe_match {
                if m.vulnerable && !vulnerable_configuration.contains(&m.cpe23_uri) {
                    vulnerable_configuration.push(m.cpe23_uri);
                }
            }
        }

        let mut references = vec![];
        for reference in cve_item.cve.references.reference_data {
            if !references.contains(&reference.url) {
                references.push(reference.url);
            }
        }

        let impact_availability = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.availability_impact.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.availability_impact.clone()),
                None => None
            }
        };
        let impact_confidentiality = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.confidentiality_impact.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.confidentiality_impact.clone()),
                None => None
            }
        };
        let impact_integrity = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.integrity_impact.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.integrity_impact.clone()),
                None => None
            }
        };
        let impact = Impact {
            availability: impact_availability,
            confidentiality: impact_confidentiality,
            integrity: impact_integrity,
        };

        let access_authentication = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.privileges_required.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.authentication.clone()),
                None => None
            }
        };
        let access_complexity = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.attack_complexity.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.access_complexity.clone()),
                None => None
            }
        };
        let access_vector = match &cve_item.impact.base_metric_v3 {
            Some(v3) => Some(v3.cvss_v3.attack_vector.clone()),
            None => match &cve_item.impact.base_metric_v2 {
                Some(v2) => Some(v2.cvss_v2.access_vector.clone()),
                None => None
            }
        };
        let access = Access {
            authentication: access_authentication,
            complexity: access_complexity,
            vector: access_vector
        };

        Cve {
            modified: modified.format("%Y-%m-%dT%H:%M:%S").to_string(),
            published: published.format("%Y-%m-%dT%H:%M:%S").to_string(),
            access,
            assigner: cve_item.cve.cve_data_meta.assigner,
            capec: vec![],
            cvss,
            cvss_time: None,
            cvss_vector: None,
            cwe,
            id: cve_item.cve.cve_data_meta.id,
            impact,
            last_modified: modified.format("%Y-%m-%dT%H:%M:%S").to_string(),
            references,
            summary: cve_item.cve.description.description_data[0].value.clone(),
            vulnerable_configuration,
            vulnerable_configuration_cpe22: vec![],
            vulnerable_product: vec![]
        }
    }
}
