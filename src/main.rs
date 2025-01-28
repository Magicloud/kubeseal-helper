use anyhow::{Result, anyhow};
use base64_stream::ToBase64Reader;
use clap::error::ErrorKind;
use clap::*;
use std::fs::File;
use std::io::{Read, Write, stdin};
use std::path::{Path, PathBuf};
use std::process as p;

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.secret_name.is_none() {
        Cli::command().error(
            ErrorKind::MissingRequiredArgument,
            "the following required arguments were not provided:\n  \x1b[32m--secret-name <SECRET_NAME>\x1b[0m"
        ).exit();
    }
    let secret_name = cli.secret_name.unwrap(); // handled above

    let pg = passwords::PasswordGenerator {
        length: cli.generated_secret_length.into(),
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: true,
        strict: true,
    };
    let secret = if cli.read_stdin {
        let mut buf = String::new();
        stdin().read_line(&mut buf)?;
        buf
    } else {
        pg.generate_one().map_err(|e| anyhow!("{e}"))?
    };

    let manifest = match cli.cmd {
        SubCmd::UserPass { username } => {
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
                username, secret, secret_name, cli.secret_namespace
            )
        }
        SubCmd::File { file } => {
            let base64 = base64(&file)?;
            format!(
                r#"
apiVersion: v1
data:
  "{}": {}
kind: Secret
metadata:
  name: {}
  namespace: {}
type: Opaque
"#,
                file.file_name()
                    .ok_or(anyhow!(
                        "Cannot extract filename from {}",
                        file.to_string_lossy()
                    ))?
                    .to_string_lossy(),
                base64,
                secret_name,
                cli.secret_namespace
            )
        }
        SubCmd::Tls { crt, key } => {
            let crt_data = base64(&crt)?;
            let key_data = base64(&key)?;
            format!(
                r#"
apiVersion: v1
data:
  tls.crt: {}
  tls.key: {}
kind: Secret
metadata:
  name: {}
  namespace: {}
type: kubernetes.io/tls
"#,
                crt_data, key_data, secret_name, cli.secret_namespace
            )
        }
        SubCmd::AlterUserPass {
            username,
            alter_username_key,
            alter_password_key,
        } => {
            format!(
                r#"
apiVersion: v1
stringData:
  {}: {}
  {}: {}
kind: Secret
metadata:
  name: {}
  namespace: {}
type: Opaque
"#,
                alter_username_key,
                username,
                alter_password_key,
                secret,
                secret_name,
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
    UserPass {
        username: String,
    },
    File {
        file: PathBuf,
    },
    Tls {
        #[arg(short, long)]
        crt: PathBuf,
        #[arg(short, long)]
        key: PathBuf,
    },
    AlterUserPass {
        username: String,
        alter_username_key: String,
        alter_password_key: String,
    },
}

#[derive(Parser)]
struct Cli {
    #[arg(short('s'), long, global = true)]
    secret_name: Option<String>,
    #[arg(short('n'), long, global = true, default_value = "default")]
    secret_namespace: String,
    #[arg(short('l'), long, global = true, default_value = "16")]
    generated_secret_length: u8,
    #[arg(short, long, global = true, default_value = "false")]
    read_stdin: bool,

    #[command(subcommand)]
    cmd: SubCmd,
}

fn base64(file: &Path) -> Result<String> {
    let f = File::open(&file)?;
    let mut encoder = ToBase64Reader::new(f);
    let mut base64 = String::new();
    encoder.read_to_string(&mut base64)?;
    Ok(base64)
}
