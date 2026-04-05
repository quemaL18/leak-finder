use clap::Parser;
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
struct Args {
    path: PathBuf,

    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    #[arg(long)]
    extensions: Option<String>,

    #[arg(long, default_value_t = 1000000)]
    max_size: u64,
}

#[derive(Debug)]
struct ScanResult {
    path: String,
    issues: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let extensions: Option<Vec<String>> = args.extensions.as_ref().map(|ext| {
        ext.split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    });

    let max_size: u64 = 1_000_000; // 1 мб

    let mut total_files: i32 = 0;
    let mut checked_files: i32 = 0;
    let mut skipped_large_files: i32 = 0;
    let mut warnings_count: i32 = 0;

    let mut results: Vec<ScanResult> = Vec::new();

    let mut walker = WalkDir::new(&args.path);

    if !args.recursive {
        walker = walker.max_depth(1);
    }

    for result in walker.into_iter() {
        match result {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    total_files += 1;

                    let path = entry.path();

                    if let Some(exts) = &extensions {
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if !exts.contains(&ext.to_lowercase()) {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    match fs::metadata(path) {
                        Ok(metadata) => {
                            if metadata.len() > max_size {
                                skipped_large_files += 1;
                                println!(
                                    "[INFO] skipped large file: {} ({} bytes)",
                                    path.display(),
                                    metadata.len()
                                );
                                continue;
                            }
                        }
                        Err(error) => {
                            println!(
                                "[ERROR] failed to get metadata for {}: {}",
                                path.display(),
                                error
                            );
                            continue;
                        }
                    }

                    match fs::read_to_string(path) {
                        Ok(content) => {
                            checked_files += 1;

                            let content_lower = content.to_lowercase();
                            let mut issues: Vec<String> = Vec::new();

                            if content_lower.contains("password") {
                                issues.push("password".to_string());
                            }

                            if content_lower.contains("token") {
                                issues.push("token".to_string());
                            }

                            if content_lower.contains("secret") {
                                issues.push("secret".to_string());
                            }

                            if content_lower.contains("api_key") {
                                issues.push("api_key".to_string());
                            }

                            if content_lower.contains("пароль") {
                                issues.push("пароль".to_string());
                            }

                            if content_lower.contains("токен") {
                                issues.push("токен".to_string());
                            }

                            if content_lower.contains("username") {
                                issues.push("username".to_string());
                            }

                            if !issues.is_empty() {
                                warnings_count += issues.len() as i32;

                                results.push(ScanResult {
                                    path: path.display().to_string(),
                                    issues,
                                });
                            }
                        }
                        Err(error) => {
                            println!(
                                "[ERROR] failed to read file {}: {}",
                                path.display(),
                                error
                            );
                        }
                    }
                }
            }
            Err(error) => {
                println!("[ERROR] failed to access entry: {}", error);
            }
        }
    }

    println!("\nНайденные проблемы:");
    if results.is_empty() {
        println!("Совпадений не найдено.");
    } else {
        for result in &results {
            println!("Файл: {}", result.path);
            for issue in &result.issues {
                println!("  - {}", issue);
            }
        }
    }

    println!("\nСканирование завершено.");
    println!("Всего файлов найдено: {}", total_files);
    println!("Файлов проверено: {}", checked_files);
    println!("Пропущено больших файлов: {}", skipped_large_files);
    println!("Всего предупреждений: {}", warnings_count);
}