use std::fmt::Debug;
use std::path::Path;
use std::str::FromStr;

use anyhow::Result;
use rusqlite::Connection as SqliteConnection;

use crate::structs::{DataElementOccurrence, Vulnerability};

pub struct ScanDatabase {
    conn: SqliteConnection,
}

/// Database for recording and querying information extracted from scans.
impl ScanDatabase {
    pub fn new(file_path: &Path) -> Self {
        let conn = SqliteConnection::open(file_path).unwrap();
        conn.execute_batch(
            "
            BEGIN;

            DROP TABLE IF EXISTS data_element_occurrences;
            CREATE TABLE data_element_occurrences(
                data_element_id TEXT,
                data_element_name TEXT,
                hash TEXT,
                sensitivity VARCHAR(10),
                language VARCHAR(10),
                code_segment TEXT,
                absolute_file_path TEXT,
                relative_file_path TEXT,
                line_start INT,
                line_end INT,
                column_start INT,
                column_end INT,
                url_link TEXT,
                source TEXT,
                tags TEXT
            );

            DROP TABLE IF EXISTS vulnerabilities;
            CREATE TABLE vulnerabilities(
                data_sink_id TEXT,
                data_element_ids TEXT,
                data_element_names TEXT,
                hash TEXT,
                description TEXT,
                severity VARCHAR(10),
                language VARCHAR(10),
                code_segment TEXT,
                absolute_file_path TEXT,
                relative_file_path TEXT,
                line_start INT,
                line_end INT,
                column_start INT,
                column_end INT,
                url_link TEXT,
                cwe TEXT,
                owasp TEXT
            );

            COMMIT;
            ",
        )
        .unwrap();
        Self { conn }
    }

    pub fn put_data_element_occurrence(&self, occurrence: &DataElementOccurrence) -> Result<()> {
        self.conn.execute(
            "INSERT INTO data_element_occurrences (
                data_element_id,
                data_element_name,
                hash,
                sensitivity,
                language,
                code_segment,
                absolute_file_path,
                relative_file_path,
                line_start,
                line_end,
                column_start,
                column_end,
                url_link,
                source,
                tags
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            [
                &occurrence.data_element_id,
                &occurrence.data_element_name,
                &occurrence.hash,
                &occurrence.sensitivity.to_string(),
                &occurrence.language.to_string(),
                &occurrence.code_segment,
                &occurrence.absolute_file_path,
                &occurrence.relative_file_path,
                &occurrence.line_start.to_string(),
                &occurrence.line_end.to_string(),
                &occurrence.column_start.to_string(),
                &occurrence.column_end.to_string(),
                &occurrence.url_link,
                &occurrence.source.to_string(),
                &occurrence.tags.join(","),
            ],
        )?;
        Ok(())
    }

    pub fn get_data_element_occurrences(&self) -> Result<Vec<DataElementOccurrence>> {
        let mut statement = self.conn.prepare(
            "SELECT
                data_element_id,
                data_element_name,
                hash,
                sensitivity,
                language,
                code_segment,
                absolute_file_path,
                relative_file_path,
                line_start,
                line_end,
                column_start,
                column_end,
                url_link,
                source,
                tags
            FROM data_element_occurrences",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(DataElementOccurrence {
                data_element_id: row.get(0)?,
                data_element_name: row.get(1)?,
                hash: row.get(2)?,
                sensitivity: row_to_enum(row, 3),
                language: row_to_enum(row, 4),
                code_segment: row.get(5)?,
                absolute_file_path: row.get(6)?,
                relative_file_path: row.get(7)?,
                line_start: row.get(8)?,
                line_end: row.get(9)?,
                column_start: row.get(10)?,
                column_end: row.get(11)?,
                url_link: row.get(12)?,
                source: row_to_enum(row, 13),
                tags: row_to_vec(row, 14),
            })
        })?;
        Ok(rows.map(Result::unwrap).collect())
    }

    pub fn put_vulnerability(&self, vulnerability: &Vulnerability) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vulnerabilities (
                data_sink_id,
                data_element_ids,
                data_element_names,
                hash,
                description,
                severity,
                language,
                code_segment,
                absolute_file_path,
                relative_file_path,
                line_start,
                line_end,
                column_start,
                column_end,
                url_link,
                cwe,
                owasp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            [
                &vulnerability.data_sink_id,
                &vulnerability.data_element_ids.join(","),
                &vulnerability.data_element_names.join(","),
                &vulnerability.hash,
                &vulnerability.description,
                &vulnerability.severity.to_string(),
                &vulnerability.language.to_string(),
                &vulnerability.code_segment,
                &vulnerability.absolute_file_path,
                &vulnerability.relative_file_path,
                &vulnerability.line_start.to_string(),
                &vulnerability.line_end.to_string(),
                &vulnerability.column_start.to_string(),
                &vulnerability.column_end.to_string(),
                &vulnerability.url_link,
                &vulnerability.cwe.join(","),
                &vulnerability.owasp.join(","),
            ],
        )?;
        Ok(())
    }

    pub fn get_vulnerabilities(&self) -> Result<Vec<Vulnerability>> {
        let mut statement = self.conn.prepare(
            "SELECT
                data_sink_id,
                data_element_ids,
                data_element_names,
                hash,
                description,
                severity,
                language,
                code_segment,
                absolute_file_path,
                relative_file_path,
                line_start,
                line_end,
                column_start,
                column_end,
                url_link,
                cwe,
                owasp
            FROM vulnerabilities",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(Vulnerability {
                data_sink_id: row.get(0)?,
                data_element_ids: row_to_vec(row, 1),
                data_element_names: row_to_vec(row, 2),
                hash: row.get(3)?,
                description: row.get(4)?,
                severity: row_to_enum(row, 5),
                language: row_to_enum(row, 6),
                code_segment: row.get(7)?,
                absolute_file_path: row.get(8)?,
                relative_file_path: row.get(9)?,
                line_start: row.get(10)?,
                line_end: row.get(11)?,
                column_start: row.get(12)?,
                column_end: row.get(13)?,
                url_link: row.get(14)?,
                cwe: row_to_vec(row, 15),
                owasp: row_to_vec(row, 16),
            })
        })?;
        Ok(rows.map(Result::unwrap).collect())
    }
}

fn row_to_enum<T: FromStr>(row: &rusqlite::Row, index: usize) -> T
where
    <T as FromStr>::Err: Debug,
{
    row.get::<_, String>(index).unwrap().parse().unwrap()
}

fn row_to_vec(row: &rusqlite::Row, index: usize) -> Vec<String> {
    row.get::<_, String>(index)
        .unwrap()
        .split(',')
        .map(String::from)
        .collect::<Vec<String>>()
}
