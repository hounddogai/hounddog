use tabled::builder::Builder;
use tabled::settings::Style;

pub fn print_table<H, C>(header: Vec<H>, rows: Vec<Vec<C>>)
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    if rows.is_empty() {
        return;
    }
    let mut table_builder = Builder::default();

    // Add the header
    table_builder.push_record(header.iter().map(|h| h.as_ref()));

    // Add the rows
    rows.iter().for_each(|row| {
        table_builder.push_record(row.iter().map(|cell| cell.as_ref()));
    });
    println!("{}", table_builder.build().with(Style::sharp()).to_string());
}