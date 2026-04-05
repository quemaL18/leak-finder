use clap::Parser;
use std::fs;
use std::path::PathBuf;
use serde::Serialize;
use chrono::Local;
use walkdir::WalkDir;
use regex::Regex;


#[derive(Parser, Debug)]
struct Args {
    path: PathBuf,

    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    #[arg(long)]
    extensions: Option<String>,

    #[arg(long, default_value_t = 1000000)]
    max_size: u64,

    #[arg(long, short)]
    output: Option<PathBuf>,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Debug, Serialize)]
struct ScanResult {
    path: String,
    issues: Vec<String>,
}
#[derive(Serialize)]
struct ScanReport {
    timestamp: String,
    scan_path: String,
    recursive: bool,
    max_size: u64,
    total_files: i32,
    checked_files: i32,
    skipped_large_files: i32,
    warnings_count: i32,
    results: Vec<ScanResult>,
    verbose: bool,
}

fn get_patterns() -> Vec<(String, Regex)> {
    vec![
        ("email".to_string(), Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()),
        ("jwt_token".to_string(), Regex::new(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap()),
        ("uuid".to_string(), Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap()),
        ("credit_card".to_string(), Regex::new(r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}").unwrap()),
        ("password".to_string(), Regex::new(r"(?i)password").unwrap()),
        ("token".to_string(), Regex::new(r"(?i)token").unwrap()),
        ("secret".to_string(), Regex::new(r"(?i)secret").unwrap()),
        ("api_key".to_string(), Regex::new(r"(?i)api[_-]?key").unwrap()),
        ("пароль".to_string(), Regex::new(r"(?i)пароль").unwrap()),
        ("токен".to_string(), Regex::new(r"(?i)токен").unwrap()),
        ("username".to_string(), Regex::new(r"(?i)username").unwrap()),
        ("generic_token".to_string(), Regex::new(r"[a-zA-Z0-9]{40,}").unwrap()),
    
    ]
}
fn main() {
    let args = Args::parse();

    if args.verbose {
        println!("[ПОДРОБНО] Запуск сканирования с параметрами:");
        println!("[ПОДРОБНО]   Путь: {}", args.path.display());
        println!("[ПОДРОБНО]   Рекурсивно: {}", args.recursive);
        println!("[ПОДРОБНО]   Макс. размер: {} байт", args.max_size);
        println!("[ПОДРОБНО]   Выходной файл: {:?}", args.output);
    }

    let extensions: Option<Vec<String>> = args.extensions.as_ref().map(|ext| {
        ext.split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    });

    let mut total_files: i32 = 0;
    let mut checked_files: i32 = 0;
    let mut skipped_large_files: i32 = 0;
    let mut warnings_count: i32 = 0;

    let mut results: Vec<ScanResult> = Vec::new();

    let mut walker = WalkDir::new(&args.path);

    if !args.recursive {
        walker = walker.max_depth(1);
        if args.verbose {
            println!("[ПОДРОБНО] Не рекурсивный режим. Поиск только в текущей папке.")
        }
    }

    for result in walker.into_iter() {
        match result {
            Ok(entry) => {
                if entry.file_type().is_file() {
                    total_files += 1;

                    let path = entry.path();

                    if args.verbose{
                        println!("[ПОДРОБНО] Найден файл: {}", path.display())
                    }

                    if let Some(exts) = &extensions {
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if !exts.contains(&ext.to_lowercase()) {
                                if args.verbose {
                                    println!("[ПОДРОБНО] Пропущено фильтром (не в {:?})" , exts)
                                }
                                continue;
                            }
                        } else {
                            if args.verbose {
                                println!("[ПОДРОБНО]   Пропущен - нет расширения файла");
                            }
                            continue;
                        }
                    }

                    match fs::metadata(path) {
                        Ok(metadata) => {
                            if metadata.len() > args.max_size {
                                skipped_large_files += 1;
                                if args.verbose {
                                    println!("[ПОДРОБНО]   Пропущен - файл слишком большой ({} байт > {} байт)", metadata.len(), args.max_size);
                                } else {
                                    println!(
                                        "[INFO] Пропущен большой файл: {} ({} байт)",
                                        path.display(),
                                        metadata.len()
                                    );
                                }
                                continue;
                            }
                        }
                        Err(error) => {
                            println!(
                                "[ОШИБКА] Не удалось получить метаданные для {}: {}",
                                path.display(),
                                error
                            );
                            continue;
                        }
                    }
                     if args.verbose {
                        println!("[ПОДРОБНО]   Чтение содержимого файла...");
                    }
                    match fs::read_to_string(path) {
                        Ok(content) => {
                            checked_files += 1;

                            let mut issues: Vec<String> = Vec::new();
                            let patterns = get_patterns();

                            for (name, regex) in patterns {
                                if regex.is_match(&content) {
                                    issues.push(name.clone());
                                    if args.verbose {
                                        println!("[ПОДРОБНО]   Найден паттерн: {}", name);
                                    }
                                }
                            }

                        if !issues.is_empty() {
                            warnings_count += issues.len() as i32;
                            
                            if args.verbose {
                                println!("[ПОДРОБНО]   Всего проблем в файле: {}", issues.len());
                            }
                            
                            results.push(ScanResult {
                                path: path.display().to_string(),
                                issues,
                            });
                        } else if args.verbose {
                            println!("[ПОДРОБНО]   Проблем не найдено");
                        }
                        }
                        Err(error) => {
                            println!(
                                "[ОШИБКА] Не удалось прочитать файл {}: {}",
                                path.display(),
                                error
                            );
                        }
                    }
                }
            }
            Err(error) => {
                println!("[ОШИБКА] Не удалось получить доступ к элементу: {}", error);
            }
        }
    }

    let report = ScanReport {
        timestamp: Local::now().format("%Y-%d-%m %H:%M:%S").to_string(),
        scan_path: args.path.display().to_string(),
        recursive: args.recursive,
        max_size: args.max_size,
        total_files,
        checked_files,
        skipped_large_files,
        warnings_count,
        results,
        verbose: args.verbose,
    };

    if let Some(output_path) = &args.output {
        let json = serde_json::to_string_pretty(&report).unwrap();
        fs::write(output_path, json).unwrap();
        println!("Результаты сохранены в файл: {}", output_path.display());
    } else {
        println!("Найденные проблемы:");
        if report.results.is_empty() {
            println!("Совпадений не найдено.");
        } else {
            for result in &report.results {
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
}
