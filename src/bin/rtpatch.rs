use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rtptool::{FileRecord, RecordType, RtpError, RtpPatch};

#[derive(Parser)]
#[command(name = "rtptool", about = "Inspect, extract, and apply RTPatch (.rtp) files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode every 0x0320 compressed body and validate ADD destinations.
    Verify { rtp_file: PathBuf, #[arg(long)] programs: bool },
    /// Show header info and record summary.
    Inspect {
        rtp_file: PathBuf,
        #[arg(short, long)]
        verbose: bool,
    },

    /// List all file records.
    List {
        rtp_file: PathBuf,
        /// Filter by record type: modify, add, metadata, new, rename, delete, mkdir, all (default: all).
        #[arg(short = 't', long, default_value = "all")]
        record_type: String,
    },

    /// Extract raw compressed diffs or NEW file metadata.
    Extract {
        rtp_file: PathBuf,
        /// Output directory.
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
        /// Only extract this specific filename (substring match).
        #[arg(short, long)]
        file: Option<String>,
        /// Extract NEW record metadata only (no diff bytes to extract from NEW records).
        #[arg(long)]
        new_only: bool,
    },

    /// Apply MODIFY patches, or 0x0320 HISTORY/ADD/DELETE actions.
    Apply {
        rtp_file: PathBuf,
        /// Directory containing original (unpatched) source files.
        #[arg(short, long)]
        source: PathBuf,
        /// Directory to write patched files into.
        #[arg(short, long)]
        output: PathBuf,
        /// Only apply patch for this filename (substring match).
        #[arg(short, long)]
        file: Option<String>,
        /// For single-file mode: write output to this exact path instead of --output/<name>.
        #[arg(long)]
        out_file: Option<PathBuf>,
        /// Skip legacy source checksums (0x0320 always requires validation).
        #[arg(long)]
        no_checksum: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn load_patch(path: &Path) -> Result<RtpPatch, RtpError> {
    let data = fs::read(path).map_err(RtpError::Io)?;
    rtptool::parse(data)
}

fn filter_filename(rec: &FileRecord, filter: &Option<String>) -> bool {
    match filter {
        None => true,
        Some(f) => rec.filename.to_lowercase().contains(&f.to_lowercase()),
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Verify { rtp_file, programs } => {
            let p = load_patch(&rtp_file)?;
            let mut streams = 0;
            let mut expanded = 0u64;
            let mut adds = 0;
            let mut opcode_counts = [0u64; 23];
            let mut checked_programs = 0;
            for rec in &p.records {
                let steps = if rec.rec_type == RecordType::History { rec.children.as_slice() } else { std::slice::from_ref(rec) };
                for step in steps.iter().filter(|s| s.has_diff()) {
                    let data = rtptool::decode_record(&p, step)?;
                    if step.rec_type == RecordType::Add {
                        if !rtptool::descriptor_matches(&data, &step.dst_entries[0]) {
                            return Err(format!("ADD checksum mismatch: {}", step.filename).into());
                        }
                        adds += 1;
                    }
                    if programs && step.rec_type == RecordType::Modify {
                        let counts = rtptool::apply::validate_program(&data, step.src_entries[0].file_size as usize, step.new_file_size as usize)
                            .map_err(|e| format!("{}: {e}", step.filename))?;
                        for (total, n) in opcode_counts.iter_mut().zip(counts) { *total += n; }
                        checked_programs += 1;
                    }
                    expanded += data.len() as u64;
                    streams += 1;
                }
            }
            println!("Verified: {streams} streams, {expanded} expanded bytes, {adds} ADD checksums");
            if programs { println!("Programs: {checked_programs}; opcode counts: {opcode_counts:?}"); }
        }
        Command::Inspect { rtp_file, verbose } => {
            let p = load_patch(&rtp_file)?;
            let h = &p.header;

            println!("File   : {}", rtp_file.display());
            println!("Version: {}.{:02} (0x{:04x})", h.version >> 8, h.version & 0xFF, h.version);
            println!("Flags  : 0x{:04x}", h.flags);
            if h.version == 0x0320 {
                println!("Opaque : {:02x?}", h.opaque);
            } else { println!("Payload: {} bytes", h.patch_total_size); }
            println!("ExtraMd: {}", h.extra_mode);
            println!("Dirs   : {}", p.dirs.len());
            println!("Records: {}", p.records.len());

            if verbose && !p.dirs.is_empty() {
                println!();
                for (i, d) in p.dirs.iter().enumerate() {
                    println!("  dir[{i}] = {d:?}");
                }
            }

            println!();
            let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
            for rec in &p.records {
                *counts.entry(rec.rec_type.as_str()).or_default() += 1;
            }
            for (t, n) in &counts { println!("  {t:7}: {n}"); }
            if h.version == 0x0320 {
                let mut actions: std::collections::BTreeMap<&str, usize> = Default::default();
                for step in p.operations() { *actions.entry(step.rec_type.as_str()).or_default() += 1; }
                println!("Actions: {actions:?}");
            }

            if verbose {
                println!();
                for rec in &p.records {
                    let size = if rec.new_file_size > 0 {
                        format!("{:>10} B", rec.new_file_size)
                    } else {
                        " ".repeat(11)
                    };
                    let diff = if rec.patch_data_size > 0 {
                        format!(" diff={}", rec.patch_data_size)
                    } else {
                        String::new()
                    };
                    println!("  [{:6}] {size}{diff}  {}", rec.rec_type.as_str(), rec.filename);
                }
            }
        }

        Command::List { rtp_file, record_type } => {
            let p = load_patch(&rtp_file)?;
            let type_filter = record_type.to_lowercase();

            println!("{:<8} {:>10}  {:>10}  filename", "type", "dest_size", "diff_size");
            println!("{}", "-".repeat(60));

            for rec in p.operations().filter(|r| {
                type_filter == "all" || r.rec_type.as_str().to_lowercase() == type_filter
            }) {
                let size = if rec.new_file_size > 0 {
                    format!("{:>10}", rec.new_file_size)
                } else {
                    " ".repeat(10)
                };
                let diff = if rec.patch_data_size > 0 {
                    format!("{:>10}", rec.patch_data_size)
                } else {
                    " ".repeat(10)
                };
                println!("{:<8} {size}  {diff}  {}", rec.rec_type.as_str(), rec.filename);
            }
        }

        Command::Extract { rtp_file, out, file, new_only } => {
            let p = load_patch(&rtp_file)?;
            fs::create_dir_all(&out)?;

            if new_only {
                let records: Vec<_> = p.records.iter()
                    .filter(|r| r.rec_type == RecordType::New && filter_filename(r, &file))
                    .collect();
                println!("NEW records ({}): no inline data in patch", records.len());
                let meta = out.join(".new_files.txt");
                let mut lines = format!(
                    "# NEW files in {}\n# filename\texpected_size\n",
                    rtp_file.display()
                );
                for rec in &records {
                    println!("  {:>10} B  {}", rec.new_file_size, rec.filename);
                    lines.push_str(&format!("{}\t{}\n", rec.filename, rec.new_file_size));
                }
                fs::write(&meta, &lines)?;
                println!("Metadata -> {}", meta.display());
                return Ok(());
            }

            let records: Vec<_> = p.operations()
                .filter(|r| r.has_diff() && filter_filename(r, &file))
                .collect();

            println!("Extracting {} compressed diffs to {}/", records.len(), out.display());
            for rec in records {
                let safe = rec.filename.replace(['\\', '/'], "_");
                let name = if p.header.version == 0x0320 { format!("{safe}.{:x}.diff", rec.patch_data_offset) } else { format!("{safe}.diff") };
                let dest = out.join(name);
                let diff = &p.raw[rec.patch_data_offset..rec.patch_data_offset + rec.patch_data_size];
                fs::write(&dest, diff)?;
                println!("  {} -> {} ({} B)", rec.filename, dest.display(), rec.patch_data_size);
            }
        }

        Command::Apply { rtp_file, source, output, file, out_file, no_checksum } => {
            let p = load_patch(&rtp_file)?;
            if p.header.version == 0x0320 {
                if no_checksum { return Err("0x0320 history selection requires checksums".into()); }
                return apply_0320(&p, &source, &output, &file, out_file.as_deref());
            }
            fs::create_dir_all(&output)?;

            let records: Vec<_> = p.records.iter()
                .filter(|r| r.has_diff() && filter_filename(r, &file))
                .collect();

            if records.is_empty() {
                println!("No MODIFY records match.");
                return Ok(());
            }

            if out_file.is_some() && records.len() > 1 {
                eprintln!("error: --out-file requires --file to match exactly one record");
                std::process::exit(1);
            }

            println!("Applying {} MODIFY patch(es):", records.len());
            println!("  source : {}", source.display());
            println!("  output : {}", output.display());
            println!();

            let mut ok = 0usize;
            let mut skip = 0usize;
            let mut err = 0usize;

            for rec in &records {
                let rel = rec.filename.replace('\\', std::path::MAIN_SEPARATOR_STR);
                let src_path = source.join(&rel);
                let dst_path = if let Some(ref of) = out_file {
                    of.clone()
                } else {
                    output.join(&rel)
                };

                if !src_path.exists() {
                    eprintln!("  [SKIP]  {} -- source not found: {}", rec.filename, src_path.display());
                    skip += 1;
                    continue;
                }

                let src_data = match fs::read(&src_path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("  [ERR]   {} -- read source: {e}", rec.filename);
                        err += 1;
                        continue;
                    }
                };

                match rtptool::patch_file(&p, rec, &src_data, !no_checksum) {
                    Ok(patched) => {
                        if let Some(Err(e)) = dst_path.parent().map(fs::create_dir_all) {
                            eprintln!("  [ERR]   {} -- create dir: {e}", rec.filename);
                            err += 1;
                            continue;
                        }
                        match fs::write(&dst_path, &patched) {
                            Ok(()) => {
                                println!(
                                    "  [OK]    {}  {} B -> {} B  ({})",
                                    rec.filename, src_data.len(), patched.len(), dst_path.display()
                                );
                                ok += 1;
                            }
                            Err(e) => {
                                eprintln!("  [ERR]   {} -- write output: {e}", rec.filename);
                                err += 1;
                            }
                        }
                    }
                    Err(RtpError::ChecksumMismatch { filename, expected, actual }) => {
                        eprintln!(
                            "  [SKIP]  {filename} -- CRC mismatch \
                             (expected 0x{expected:08x}, got 0x{actual:08x}); \
                             use --no-checksum to apply anyway"
                        );
                        skip += 1;
                    }
                    Err(e) => {
                        eprintln!("  [ERR]   {} -- {e}", rec.filename);
                        err += 1;
                    }
                }
            }

            println!();
            println!("Done: {ok} patched, {skip} skipped, {err} errors");
            if err > 0 {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}


fn relative_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let normalized = name.replace('\\', "/");
    if normalized.is_empty() || normalized.starts_with('/') || normalized.contains(':')
        || normalized.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return Err(format!("unsafe patch pathname: {name:?}").into());
    }
    Ok(PathBuf::from(normalized))
}

// DOS/long spelling is retained in the model; portable lookup uses full paths.
fn source_path(root: &Path, rel: &Path) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let mut current = root.to_path_buf();
    for part in rel.components() {
        let name = part.as_os_str();
        if !current.is_dir() { return Ok(None); }
        let mut matches = fs::read_dir(&current)?.filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(&name.to_string_lossy()))
            .map(|e| e.path()).collect::<Vec<_>>();
        if matches.len() > 1 { return Err(format!("ambiguous case-insensitive path: {}", rel.display()).into()); }
        let Some(next) = matches.pop() else { return Ok(None); };
        if fs::symlink_metadata(&next)?.file_type().is_symlink() { return Err("symlink in patch path".into()); }
        current = next;
    }
    Ok(Some(current))
}

fn apply_0320(p: &RtpPatch, source: &Path, output: &Path, filter: &Option<String>, out_file: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output)?;
    let source = source.canonicalize()?;
    let output = output.canonicalize()?;
    if source.starts_with(&output) || output.starts_with(&source) {
        return Err("0x0320 source and output trees must be separate".into());
    }
    let records: Vec<_> = p.records.iter().filter(|r| filter_filename(r, filter)).collect();
    if out_file.is_some() && records.len() != 1 { return Err("--out-file requires exactly one record".into()); }
    let mut ok = 0;
    let mut deleted = 0;
    let mut errors = 0;
    for rec in records {
        let rel = relative_path(&rec.filename)?;
        let input = source_path(&source, &rel)?.map(fs::read).transpose()?;
        match rtptool::apply_record(p, rec, input.as_deref()) {
            Ok(result) => {
                // Respect existing output casing when overlaying on a case-sensitive host.
                let dest = if let Some(path) = out_file {
                    path.to_path_buf()
                } else { staging_path(&output, &rel)? };
                if let Some(data) = result {
                    if let Some(parent) = dest.parent() { fs::create_dir_all(parent)?; }
                    let parent = dest.parent().unwrap().canonicalize()?;
                    if parent.starts_with(&source) || fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
                        return Err("output would overwrite an input or follow a symlink".into());
                    }
                    // Refuse symlink parents introduced outside the source tree.
                    if out_file.is_none() {
                        let parent = dest.parent().unwrap().canonicalize()?;
                        if !parent.starts_with(&output) { return Err("output path escapes staging tree".into()); }
                    }
                    fs::write(&dest, &data)?;
                    println!("  [OK] {} {} B", rec.filename, data.len());
                    ok += 1;
                } else {
                    if dest.exists() {
                        if dest.canonicalize()?.starts_with(&source)
                            || fs::symlink_metadata(&dest)?.file_type().is_symlink() {
                            return Err("DELETE output would remove an input or follow a symlink".into());
                        }
                        fs::remove_file(&dest)?;
                    }
                    println!("  [DELETE] {}", rec.filename);
                    deleted += 1;
                }
            }
            Err(e) => { eprintln!("  [ERR] {} -- {e}", rec.filename); errors += 1; }
        }
    }
    println!("Done: {ok} produced, {deleted} deleted/absent, {errors} errors");
    if errors != 0 { return Err(format!("{errors} files could not be produced (missing or unsupported source versions)").into()); }
    Ok(())
}

fn staging_path(root: &Path, rel: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut current = root.to_path_buf();
    for part in rel.components() {
        let name = part.as_os_str();
        let existing = source_path(&current, Path::new(name))?;
        current = existing.unwrap_or_else(|| current.join(name));
    }
    Ok(current)
}
