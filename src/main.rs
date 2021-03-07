use serde_json;
use clap::Clap;
use postgres::{Client, NoTls};
use chrono::{Utc, DateTime, NaiveDateTime, Datelike};

mod circl;
mod error;
mod nvd;

use error::Result;
use circl::Cve;

#[derive(Clap)]
#[clap(version = "1.0", author = "Alexander Kjäll <alexander.kjall@gmail.com>")]
struct Opts {
    #[clap(short)]
    setup_db: bool,
    #[clap(short)]
    full_download: bool
}

fn db_connection() -> Result<Client> {
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name("settings"))?;

    Ok(Client::connect(&format!("host={} user={} dbname={} password={}",
                                settings.get_str("db-host")?,
                                settings.get_str("db-user")?,
                                settings.get_str("db-name")?,
                                settings.get_str("db-password")?), NoTls)?)
}

fn setup_db(client: &mut Client) -> Result<()> {
    client.execute("
        create table if not exists accesses (
            id serial8 primary key,
            authentication text not null,
            complexity text not null,
            vector text not null,
            unique(authentication, complexity, vector)
        )
", &vec![])?;
    client.execute("
        create table if not exists impacts (
            id serial8 primary key,
            confidentiality text not null,
            integrity text not null,
            availability text not null,
            unique(confidentiality, integrity, availability)
        )
", &vec![])?;
    client.execute("
        create table if not exists cves (
            id serial8 primary key,
            modified timestamptz not null,
            published timestamptz not null,
            access_id int8 references accesses(id) not null,
            assigner text not null,
            cvss float null,
            cvss_time timestamptz null,
            cvss_vector text null,
            cwe text not null,
            cve_id text not null,
            impact_id int8 references impacts(id) not null,
            last_modified timestamptz not null,
            summary text not null,
            unique(cve_id)
        )
", &vec![])?;
    client.execute("
        create table if not exists capec (
            id serial8 primary key,
            cve_id int8 references cves(id)
        )
", &vec![])?;
    client.execute("
        create table if not exists refs (
            id serial8 primary key,
            ref text,
            unique(ref)
        )
", &vec![])?;
    client.execute("
        create table if not exists cve_x_ref (
            cve_id int8 references cves(id),
            ref_id int8 references refs(id),
            primary key(cve_id, ref_id)
        )
", &vec![])?;
    client.execute("
        create table if not exists vulnerable_configurations (
            id serial8 primary key,
            vulnerable_configuration text,
            unique(vulnerable_configuration)
        )
", &vec![])?;
    client.execute("
        create table if not exists cve_x_vulnerable_configuration (
            cve_id int8 references cves(id),
            vulnerable_configuration_id int8 references vulnerable_configurations(id),
            primary key(cve_id, vulnerable_configuration_id)
        )
", &vec![])?;
    client.execute("
        create table if not exists vulnerable_configurations_cpe22 (
            id serial8 primary key,
            vulnerable_configuration_cpe22 jsonb,
            unique(vulnerable_configuration_cpe22)
        )
", &vec![])?;
    client.execute("
        create table if not exists cve_x_vulnerable_configuration_cpe22 (
            cve_id int8 references cves(id),
            vulnerable_configuration_cpe22_id int8 references vulnerable_configurations_cpe22(id),
            primary key(cve_id, vulnerable_configuration_cpe22_id)
        )
", &vec![])?;
    client.execute("
        create table if not exists vulnerable_products (
            id serial8 primary key,
            vulnerable_product text,
            unique(vulnerable_product)
        )
", &vec![])?;
    client.execute("
        create table if not exists cve_x_vulnerable_product (
            cve_id int8 references cves(id),
            vulnerable_product_id int8 references vulnerable_products(id),
            primary key(cve_id, vulnerable_product_id)
        )
", &vec![])?;
    Ok(())
}

fn store_cve(client: &mut Client, cve: &Cve) -> Result<()> {
    let row = client.query_one("insert into accesses(authentication, complexity, vector) values($1, $2, $3)
            on conflict(authentication, complexity, vector) do update set authentication=$1, complexity=$2, vector=$3 returning id",
                   &[cve.access.authentication.as_ref().unwrap_or(&"".to_string()),
                         cve.access.complexity.as_ref().unwrap_or(&"".to_string()),
                         cve.access.vector.as_ref().unwrap_or(&"".to_string())])?;
    let access_id: i64 = row.get("id");

    let row = client.query_one("insert into impacts(confidentiality, integrity, availability) values($1, $2, $3)
            on conflict(confidentiality, integrity, availability) do update set confidentiality=$1, integrity=$2, availability=$3 returning id",
                   &[cve.impact.confidentiality.as_ref().unwrap_or(&"".to_string()),
                         cve.impact.integrity.as_ref().unwrap_or(&"".to_string()),
                         cve.impact.availability.as_ref().unwrap_or(&"".to_string())])?;
    let impact_id: i64 = row.get("id");

    let modified: chrono::DateTime<Utc> = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&cve.modified, "%Y-%m-%dT%H:%M:%S").unwrap(), Utc);
    let published: chrono::DateTime<Utc> = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&cve.published, "%Y-%m-%dT%H:%M:%S").unwrap(), Utc);
    let cvss_time: Option<chrono::DateTime<Utc>> = match &cve.cvss_time {
        None => None,
        Some(d) => Some(DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&d, "%Y-%m-%dT%H:%M:%S").unwrap(), Utc))
    };
    let last_modified: chrono::DateTime<Utc> = DateTime::<Utc>::from_utc(NaiveDateTime::parse_from_str(&cve.last_modified, "%Y-%m-%dT%H:%M:%S").unwrap(), Utc);

    let row = client.query_one("insert into cves(modified, published,
            access_id, assigner, cvss, cvss_time, cvss_vector, cwe, cve_id, impact_id,
            last_modified, summary)
        values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        on conflict(cve_id) do update set modified=$1, published=$2, access_id=$3, assigner=$4, cvss=$5, cvss_time=$6,
            cvss_vector=$7, cwe=$8, impact_id=$10, last_modified=$11, summary=$12
        returning id", &[&modified, &published, &access_id, &cve.assigner,
            &cve.cvss, &cvss_time, &cve.cvss_vector, &cve.cwe, &cve.id, &impact_id,
            &last_modified, &cve.summary]);

    if row.is_err() {
        eprintln!("{:?}", row.as_ref().err().unwrap());
    }
    let cve_id: i64 = row?.get("id");

    client.execute("delete from cve_x_ref where cve_id = $1", &[&cve_id])?;
    for reference in &cve.references {
        let row = client.query_one("insert into refs(ref) values($1)
            on conflict(ref) do update set ref=$1 returning id", &[reference])?;
        let reference_id: i64 = row.get("id");

        client.execute("insert into cve_x_ref(cve_id, ref_id) values($1, $2)", &[&cve_id, &reference_id])?;
    }

    client.execute("delete from cve_x_vulnerable_configuration where cve_id = $1", &[&cve_id])?;
    for vulnerable_configuration in &cve.vulnerable_configuration {
        let row = client.query_one("insert into vulnerable_configurations(vulnerable_configuration) values($1)
            on conflict(vulnerable_configuration) do update set vulnerable_configuration=$1 returning id", &[vulnerable_configuration])?;
        let vulnerable_configuration_id: i64 = row.get("id");

        client.execute("insert into cve_x_vulnerable_configuration(cve_id, vulnerable_configuration_id) values($1, $2)", &[&cve_id, &vulnerable_configuration_id])?;
    }

    client.execute("delete from cve_x_vulnerable_configuration_cpe22 where cve_id = $1", &[&cve_id])?;
    for vulnerable_configuration_cpe22 in &cve.vulnerable_configuration_cpe22 {
        let row = client.query_one("insert into vulnerable_configurations_cpe22(vulnerable_configuration_cpe22) values($1)
            on conflict(vulnerable_configuration_cpe22) do update set vulnerable_configuration_cpe22=$1 returning id", &[vulnerable_configuration_cpe22])?;
        let vulnerable_configuration_cpe22_id: i64 = row.get("id");

        client.execute("insert into cve_x_vulnerable_configuration_cpe22(cve_id, vulnerable_configuration_cpe22_id) values($1, $2)", &[&cve_id, &vulnerable_configuration_cpe22_id])?;
    }

    client.execute("delete from cve_x_vulnerable_product where cve_id = $1", &[&cve_id])?;
    for vulnerable_product in &cve.vulnerable_product {
        let row = client.query_one("insert into vulnerable_products(vulnerable_product) values($1)
            on conflict(vulnerable_product) do update set vulnerable_product=$1 returning id", &[vulnerable_product])?;
        let vulnerable_product_id: i64 = row.get("id");

        client.execute("insert into cve_x_vulnerable_product(cve_id, vulnerable_product_id) values($1, $2)", &[&cve_id, &vulnerable_product_id])?;
    }
    Ok(())
}

fn main() {
    let opts: Opts = Opts::parse();

    let mut client = db_connection().unwrap();
    if opts.setup_db {
        setup_db(&mut client).unwrap();
    } else if opts.full_download {
        //for year in 2002..2003 {
        for year in 2002..Utc::now().year() {
            let root = nvd::download(year as u16).unwrap();

            for cve_item in root.cve_items {
                let cve = cve_item.into();
                store_cve(&mut client, &cve).unwrap();
            }
        }
    } else {
        let body = reqwest::blocking::get("https://cve.circl.lu/api/last")
            .unwrap().text().unwrap();

        let cves: Vec<Cve> = serde_json::from_str(&body).unwrap();

        for cve in cves {
            store_cve(&mut client, &cve).unwrap();
            //println!("{}", cve.summary);
        }
    }
}
