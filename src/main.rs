use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use silent_chrome::{install, list, uninstall, verify, Browser};

#[derive(Parser)]
#[command(name = "silent-chrome", about = "Chromium extension sideloader via Secure Preferences HMAC forging")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install an unpacked extension silently
    Install {
        /// Path to the extension directory (must contain manifest.json)
        ext_dir: PathBuf,

        #[command(flatten)]
        opts: BrowserOpts,
    },

    /// Remove a sideloaded extension by ID
    Uninstall {
        /// 32-character extension ID ([a-p] alphabet)
        ext_id: String,

        #[command(flatten)]
        opts: BrowserOpts,
    },

    /// List all extensions in the profile
    List {
        #[command(flatten)]
        opts: BrowserOpts,
    },

    /// Show browser info: seed, device ID, paths
    Info {
        #[command(flatten)]
        opts: BrowserOpts,
    },

    /// Verify MAC integrity for a specific extension
    Verify {
        /// 32-character extension ID
        ext_id: String,

        #[command(flatten)]
        opts: BrowserOpts,
    },
}

#[derive(clap::Args)]
struct BrowserOpts {
    /// Target browser
    #[arg(short, long, default_value = "chrome")]
    browser: Browser,

    /// Profile name
    #[arg(short, long, default_value = "Default")]
    profile: String,

    /// Override browser install path (for resources.pak lookup)
    #[arg(long)]
    browser_path: Option<PathBuf>,

    /// Override resources.pak path directly
    #[arg(long)]
    pak_path: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> std::io::Result<()> {
    match command {
        Command::Install { ext_dir, opts } => cmd_install(&ext_dir, &opts),
        Command::Uninstall { ext_id, opts } => cmd_uninstall(&ext_id, &opts),
        Command::List { opts } => cmd_list(&opts),
        Command::Info { opts } => cmd_info(&opts),
        Command::Verify { ext_id, opts } => cmd_verify(&ext_id, &opts),
    }
}

fn cmd_install(ext_dir: &Path, opts: &BrowserOpts) -> std::io::Result<()> {
    if !ext_dir.join("manifest.json").exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no manifest.json in {}",
                ext_dir.display()
            ),
        ));
    }

    let prefs_path = opts.browser.prefs_path(&opts.profile)?;
    if !prefs_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("preferences file not found: {}", prefs_path.display()),
        ));
    }

    let seed = opts.browser.seed(opts.pak_path.as_ref())?;
    let device_id = silent_chrome::identity_device_id()?;

    println!("[*] browser:    {}", opts.browser);
    println!("[*] profile:    {}", opts.profile);
    println!("[*] prefs:      {}", prefs_path.display());
    println!("[*] seed:       {} bytes", seed.len());
    println!("[*] device_id:  {device_id}");
    println!("[*] extension:  {}", ext_dir.display());

    let result = install(&prefs_path, ext_dir, &seed, &device_id)?;

    println!("[+] installed:  {}", result.extension_id);
    println!("[+] mac:        {}", result.mac);
    println!("[+] super_mac:  {}", result.super_mac);

    Ok(())
}

fn cmd_uninstall(ext_id: &str, opts: &BrowserOpts) -> std::io::Result<()> {
    let prefs_path = opts.browser.prefs_path(&opts.profile)?;
    let seed = opts.browser.seed(opts.pak_path.as_ref())?;
    let device_id = silent_chrome::identity_device_id()?;

    uninstall(&prefs_path, ext_id, &seed, &device_id)?;
    println!("[+] uninstalled: {ext_id}");

    Ok(())
}

fn cmd_list(opts: &BrowserOpts) -> std::io::Result<()> {
    let prefs_path = opts.browser.prefs_path(&opts.profile)?;
    let extensions = list(&prefs_path)?;

    if extensions.is_empty() {
        println!("no extensions found");
        return Ok(());
    }

    println!(
        "{:<34} {:<40} {:<10} {:<7}",
        "ID", "NAME", "VERSION", "STATE"
    );
    println!("{}", "-".repeat(91));

    for ext in &extensions {
        let state = if ext.enabled { "on" } else { "off" };
        let name: String = ext.name.chars().take(38).collect();
        println!(
            "{:<34} {:<40} {:<10} {:<7}",
            ext.id, name, ext.version, state
        );
    }

    Ok(())
}

fn cmd_info(opts: &BrowserOpts) -> std::io::Result<()> {
    let prefs_path = opts.browser.prefs_path(&opts.profile)?;
    let seed = opts.browser.seed(opts.pak_path.as_ref())?;
    let device_id = silent_chrome::identity_device_id()?;

    println!("browser:    {}", opts.browser);
    println!("profile:    {}", opts.profile);
    println!("prefs:      {}", prefs_path.display());
    println!("prefs ok:   {}", prefs_path.exists());

    let pak_path = opts
        .pak_path
        .clone()
        .or_else(|| opts.browser.pak_path().ok());
    if let Some(ref pak) = pak_path {
        println!("pak:        {}", pak.display());
        println!("pak ok:     {}", pak.exists());
    }

    println!("device_id:  {device_id}");

    if seed.is_empty() {
        println!("seed:       (empty — Linux vestigial)");
    } else if seed.iter().all(|&b| b == 0) {
        println!("seed:       (64 zero bytes — {}/Brave)", opts.browser);
    } else {
        let mut hex = String::with_capacity(seed.len() * 2);
        for b in &seed {
            let _ = write!(hex, "{b:02x}");
        }
        println!("seed:       {hex}");
    }

    Ok(())
}

fn cmd_verify(ext_id: &str, opts: &BrowserOpts) -> std::io::Result<()> {
    let prefs_path = opts.browser.prefs_path(&opts.profile)?;
    let seed = opts.browser.seed(opts.pak_path.as_ref())?;
    let device_id = silent_chrome::identity_device_id()?;

    let result = verify(&prefs_path, ext_id, &seed, &device_id)?;

    let check = |ok: bool| if ok { "PASS" } else { "FAIL" };

    println!("extension MAC:   {}", check(result.ext_mac_valid));
    println!("dev_mode MAC:    {}", check(result.dev_mac_valid));
    println!("super_mac:       {}", check(result.super_mac_valid));

    if result.ext_mac_valid && result.dev_mac_valid && result.super_mac_valid {
        println!("[+] all MACs valid");
    } else {
        println!("[-] MAC mismatch detected");
    }

    Ok(())
}
