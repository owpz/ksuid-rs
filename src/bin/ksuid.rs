use std::process;

use ksuid::Ksuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    String,
    Inspect,
    Time,
    Timestamp,
    Payload,
    Raw,
    Template,
}

fn parse_format(s: &str) -> Result<Format, String> {
    match s {
        "string" => Ok(Format::String),
        "inspect" => Ok(Format::Inspect),
        "time" => Ok(Format::Time),
        "timestamp" => Ok(Format::Timestamp),
        "payload" => Ok(Format::Payload),
        "raw" => Ok(Format::Raw),
        "template" => Ok(Format::Template),
        _ => Err(format!(
            "unknown format '{}': expected string, inspect, time, timestamp, payload, raw, or template",
            s
        )),
    }
}

fn unix_to_rfc3339(unix_secs: u64) -> String {
    let secs = unix_secs as i64;
    let days = secs.div_euclid(86400);
    let time_secs = secs.rem_euclid(86400);

    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn payload_hex(k: &Ksuid) -> String {
    let p = k.payload();
    let mut s = String::with_capacity(32);
    for &b in p.iter() {
        s.push(hex_upper(b >> 4));
        s.push(hex_upper(b & 0x0F));
    }
    s
}

fn hex_upper(nibble: u8) -> char {
    if nibble < 10 {
        (b'0' + nibble) as char
    } else {
        (b'A' + nibble - 10) as char
    }
}

fn format_ksuid(k: &Ksuid, format: Format, template: Option<&str>) {
    match format {
        Format::String => {
            println!("{}", k);
        }
        Format::Inspect => {
            let ksuid_str = k.to_string();
            let raw = k.to_hex();
            let time_str = unix_to_rfc3339(k.time());
            let timestamp = k.timestamp();
            let payload = payload_hex(k);
            println!();
            println!("REPRESENTATION:");
            println!();
            println!("  String: {}", ksuid_str);
            println!("     Raw: {}", raw);
            println!();
            println!("COMPONENTS:");
            println!();
            println!("       Time: {}", time_str);
            println!("  Timestamp: {}", timestamp);
            println!("    Payload: {}", payload);
        }
        Format::Time => {
            println!("{}", unix_to_rfc3339(k.time()));
        }
        Format::Timestamp => {
            println!("{}", k.timestamp());
        }
        Format::Payload => {
            println!("{}", payload_hex(k));
        }
        Format::Raw => {
            println!("{}", k.to_hex());
        }
        Format::Template => {
            let tmpl = template.unwrap_or("");
            let ksuid_str = k.to_string();
            let raw = k.to_hex();
            let time_str = unix_to_rfc3339(k.time());
            let timestamp = k.timestamp().to_string();
            let payload = payload_hex(k);

            let output = tmpl
                .replace("{{ .String }}", &ksuid_str)
                .replace("{{ .Raw }}", &raw)
                .replace("{{ .Time }}", &time_str)
                .replace("{{ .Timestamp }}", &timestamp)
                .replace("{{ .Payload }}", &payload)
                .replace("{{.String}}", &ksuid_str)
                .replace("{{.Raw}}", &raw)
                .replace("{{.Time}}", &time_str)
                .replace("{{.Timestamp}}", &timestamp)
                .replace("{{.Payload}}", &payload);
            println!("{}", output);
        }
    }
}

fn print_help() {
    println!(
        "\
USAGE:
    ksuid [FLAGS] [OPTIONS] [KSUIDS]...

FLAGS:
    -h, --help       Print help
    -v, --version    Print version

OPTIONS:
    -n <count>       Number of KSUIDs to generate (default: 1)
    -f <format>      Output format: string, inspect, time, timestamp, payload, raw, template
    -t <template>    Template string (used with -f template)

ARGS:
    [KSUIDS]...      KSUIDs to inspect (if provided, inspects instead of generates)"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut count: usize = 1;
    let mut format = Format::String;
    let mut template: Option<String> = None;
    let mut ksuids: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-v" | "--version" => {
                println!("ksuid {}", VERSION);
                return;
            }
            "-n" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -n requires a value");
                    process::exit(1);
                }
                match args[i].parse::<usize>() {
                    Ok(n) if n > 0 => count = n,
                    _ => {
                        eprintln!("error: -n must be a positive integer");
                        process::exit(1);
                    }
                }
            }
            "-f" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -f requires a value");
                    process::exit(1);
                }
                match parse_format(&args[i]) {
                    Ok(f) => format = f,
                    Err(e) => {
                        eprintln!("error: {}", e);
                        process::exit(1);
                    }
                }
            }
            "-t" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: -t requires a value");
                    process::exit(1);
                }
                template = Some(args[i].clone());
            }
            arg => {
                if arg.starts_with('-') {
                    eprintln!("error: unknown flag '{}'", arg);
                    process::exit(1);
                }
                ksuids.push(arg.to_string());
            }
        }
        i += 1;
    }

    if format == Format::Template && template.is_none() {
        eprintln!("error: -f template requires -t <template>");
        process::exit(1);
    }

    if ksuids.is_empty() {
        // Generate mode
        for _ in 0..count {
            let k = Ksuid::new();
            format_ksuid(&k, format, template.as_deref());
        }
    } else {
        // Inspect mode
        for s in &ksuids {
            match Ksuid::parse(s) {
                Ok(k) => format_ksuid(&k, format, template.as_deref()),
                Err(e) => {
                    eprintln!("error: invalid KSUID '{}': {}", s, e);
                    process::exit(1);
                }
            }
        }
    }
}
