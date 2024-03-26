use anyhow::{anyhow, Result};
use clap::*;
use std::io::Write;
use std::process as p;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let pg = passwords::PasswordGenerator {
        length: cli.secret_length.into(),
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };

    let manifest = match cli.cmd {
        SubCmd::PgSql { username } => {
            format!(
                r#"
apiVersion: v1
stringData:
  username: {}
  password: {}
kind: Secret
metadata:
  name: {}
  namespace: {}
type: kubernetes.io/basic-auth
"#,
                username,
                pg.generate_one().map_err(|e| anyhow!("{e}"))?,
                cli.secret_name,
                cli.secret_namespace
            )
        }
    };

    let mut kubeseal = p::Command::new("kubeseal")
        .args(["-o", "yaml"])
        .stdin(p::Stdio::piped())
        .spawn()?;
    let mut kubeseal_in = kubeseal
        .stdin
        .take()
        .ok_or(anyhow!("Could not take kubeseasl stdin"))?;
    kubeseal_in.write_all(manifest.as_bytes())?;

    Ok(())
}

#[derive(Subcommand)]
#[command(rename_all = "lower")]
enum SubCmd {
    PgSql {
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Parser)]
struct Cli {
    #[arg(short('s'), long)]
    secret_name: String,
    #[arg(short('n'), long, default_value = "default")]
    secret_namespace: String,
    #[arg(short('l'), long, default_value = "16")]
    secret_length: u8,

    #[command(subcommand)]
    cmd: SubCmd,
}
