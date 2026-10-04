//! Raw-byte admission probe for the source-pinned APS comparison.

use std::io::{self, BufRead};

use jcs_admit::{admit_with, Options};
use serde_json::{json, Value};

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("odd hex length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16);
            let low = char::from(pair[1]).to_digit(16);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high * 16 + low) as u8),
                _ => Err("invalid input hex".to_owned()),
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn qualify(value: &Value) -> Result<Value, String> {
    let raw = value["raw_hex"].as_str().ok_or("raw_hex required")?;
    let profile = value["profile"].as_str().ok_or("profile required")?;
    let options = match profile {
        "rfc8785" => Options::rfc8785(),
        "ijson" => Options::ijson(),
        "ijson-integers" => Options::ijson().integers_only(true),
        _ => return Err("unknown admission profile".to_owned()),
    };
    let raw = unhex(raw)?;
    Ok(match admit_with(&raw, &options) {
        Ok(canonical) => json!({"status": "accepted", "canonical_hex": hex(&canonical)}),
        Err(error) => {
            let debug = format!("{error:?}");
            let class = debug.split([' ', '{', '(']).next().unwrap_or("unknown");
            json!({"status": "refused", "error_class": class, "error": error.to_string()})
        }
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for line in io::stdin().lock().lines() {
        let value: Value = serde_json::from_str(&line?)?;
        let result = qualify(&value).map_err(io::Error::other)?;
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}
