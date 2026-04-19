use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use serde::Serialize;
use chrono::Local;
use walkdir::WalkDir;
use regex::Regex;
use rayon::prelude::*;

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

    #[arg(long, default_value = "medium")]
    level: String,
}

#[derive(Debug, Serialize)]
struct MatchContext {
    pattern_name: String,
    line_number: usize,
    line_content: String,
    match_position: usize,
}

#[derive(Debug, Serialize)]
struct ScanResult {
    path: String,
    issues: Vec<String>,
    contexts: Vec<MatchContext>,
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
    scan_duration_ms: u128,
}

fn get_patterns_by_level(level: &str) -> Vec<(String, Regex)> {
    let email = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    let jwt = Regex::new(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap();
    let uuid = Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap();
    let credit_card = Regex::new(r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}").unwrap();
    let password = Regex::new(r"(?i)password").unwrap();
    let token = Regex::new(r"(?i)token").unwrap();
    let secret = Regex::new(r"(?i)secret").unwrap();
    let api_key = Regex::new(r"(?i)api[_-]?key").unwrap();
    let parol = Regex::new(r"(?i)пароль").unwrap();
    let token_ru = Regex::new(r"(?i)токен").unwrap();
    let username = Regex::new(r"(?i)username").unwrap();
    let generic_token = Regex::new(r"[a-zA-Z0-9]{40,}").unwrap();

    match level {
        "low" => {
            vec![
                ("email".to_string(), email),
                ("credit_card".to_string(), credit_card),
                ("jwt_token".to_string(), jwt),
            ]
        }
        "high" => {
            let phone = Regex::new(r"\+?[\d\s\-\(\)]{10,}").unwrap();
            let ip = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
            
            vec![
                ("email".to_string(), email),
                ("jwt_token".to_string(), jwt),
                ("uuid".to_string(), uuid),
                ("credit_card".to_string(), credit_card),
                ("password".to_string(), password),
                ("token".to_string(), token),
                ("secret".to_string(), secret),
                ("api_key".to_string(), api_key),
                ("пароль".to_string(), parol),
                ("токен".to_string(), token_ru),
                ("username".to_string(), username),
                ("generic_token".to_string(), generic_token),
                ("phone".to_string(), phone),
                ("ip_address".to_string(), ip),
            ]
        }
        _ => {
            vec![
                ("email".to_string(), email),
                ("jwt_token".to_string(), jwt),
                ("uuid".to_string(), uuid),
                ("credit_card".to_string(), credit_card),
                ("password".to_string(), password),
                ("token".to_string(), token),
                ("secret".to_string(), secret),
                ("api_key".to_string(), api_key),
                ("пароль".to_string(), parol),
                ("токен".to_string(), token_ru),
                ("username".to_string(), username),
                ("generic_token".to_string(), generic_token),
            ]
        }
    }
}

fn scan_file(
    path: &PathBuf, 
    patterns: &Arc<Vec<(String, Regex)>>, 
    verbose: bool
) -> Option<ScanResult> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let mut issues: Vec<String> = Vec::new();
            let mut contexts: Vec<MatchContext> = Vec::new();
            
            for (name, regex) in patterns.iter() {
                for (line_num, line) in content.lines().enumerate() {
                    if let Some(match_pos) = regex.find(line) {
                        issues.push(name.clone());
                        contexts.push(MatchContext {
                            pattern_name: name.clone(),
                            line_number: line_num + 1,
                            line_content: line.to_string(),
                            match_position: match_pos.start(),
                        });
                        
                        if verbose {
                            println!("[ПОДРОБНО] {}:{} - найден {}", path.display(), line_num + 1, name);
                        }
                        break;
                    }
                }
            }
            
            if !issues.is_empty() {
                Some(ScanResult {
                    path: path.display().to_string(),
                    issues,
                    contexts,
                })
            } else {
                None
            }
        }
        Err(e) => {
            if verbose {
                println!("[ОШИБКА] Не удалось прочитать {}: {}", path.display(), e);
            }
            None
        }
    }
}

fn main() {
    let args = Args::parse();
    let start_time = std::time::Instant::now();

    if args.verbose {
        println!("[ПОДРОБНО] Запуск сканирования");
        println!("[ПОДРОБНО]   Путь: {}", args.path.display());
        println!("[ПОДРОБНО]   Рекурсивно: {}", args.recursive);
        println!("[ПОДРОБНО]   Макс. размер: {} байт", args.max_size);
        println!("[ПОДРОБНО]   Уровень: {}", args.level);
        if let Some(output) = &args.output {
            println!("[ПОДРОБНО]   Вывод: {}", output.display());
        }
    }

    let extensions: Option<Vec<String>> = args.extensions.as_ref().map(|ext| {
        ext.split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    });

    let mut files_to_scan: Vec<PathBuf> = Vec::new();
    let mut total_files: i32 = 0;
    let mut skipped_large_files: i32 = 0;

    let walker = if !args.recursive {
        WalkDir::new(&args.path).max_depth(1)
    } else {
        WalkDir::new(&args.path)
    };

    for entry in walker.into_iter() {
        match entry {
            Ok(entry) => {
                if !entry.file_type().is_file() {
                    continue;
                }
                
                total_files += 1;
                let path = entry.path().to_path_buf();

                if let Some(exts) = &extensions {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if !exts.contains(&ext.to_lowercase()) {
                            if args.verbose {
                                println!("[ПОДРОБНО] Пропущен (расширение): {}", path.display());
                            }
                            continue;
                        }
                    } else {
                        if args.verbose {
                            println!("[ПОДРОБНО] Пропущен (нет расширения): {}", path.display());
                        }
                        continue;
                    }
                }

                match fs::metadata(&path) {
                    Ok(metadata) => {
                        if metadata.len() > args.max_size {
                            skipped_large_files += 1;
                            if args.verbose {
                                println!("[ПОДРОБНО] Пропущен (большой): {} ({} байт)", path.display(), metadata.len());
                            }
                            continue;
                        }
                    }
                    Err(e) => {
                        println!("[ОШИБКА] Не удалось получить метаданные {}: {}", path.display(), e);
                        continue;
                    }
                }

                files_to_scan.push(path);
            }
            Err(e) => {
                println!("[ОШИБКА] Доступ к элементу: {}", e);
            }
        }
    }

    let patterns = Arc::new(get_patterns_by_level(&args.level));
    
    let results: Vec<ScanResult> = files_to_scan
        .par_iter()
        .filter_map(|path| scan_file(path, &patterns, args.verbose))
        .collect();

    let checked_files = results.len() as i32;
    let warnings_count: i32 = results.iter().map(|r| r.issues.len() as i32).sum();
    let duration = start_time.elapsed().as_millis();

    let report = ScanReport {
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        scan_path: args.path.display().to_string(),
        recursive: args.recursive,
        max_size: args.max_size,
        total_files,
        checked_files,
        skipped_large_files,
        warnings_count,
        results,
        verbose: args.verbose,
        scan_duration_ms: duration,
    };

    if let Some(output_path) = &args.output {
        let json = serde_json::to_string_pretty(&report).unwrap();
        fs::write(output_path, json).unwrap();
        println!("Результаты сохранены: {}", output_path.display());
    } else {
        println!("\nНайденные проблемы:");
        if report.results.is_empty() {
            println!("Совпадений не найдено.");
        } else {
            for result in &report.results {
                println!("\nФайл: {}", result.path);
                for context in &result.contexts {
                    println!("  [{}] Строка {}: {}", 
                        context.pattern_name, 
                        context.line_number, 
                        context.line_content.trim()
                    );
                }
            }
        }
        
        println!("\nСтатистика:");
        println!("  Время: {} мс", duration);
        println!("  Всего файлов: {}", total_files);
        println!("  Проверено: {}", checked_files);
        println!("  Пропущено (размер): {}", skipped_large_files);
        println!("  Предупреждений: {}", warnings_count);
        println!("  Уровень: {}", args.level);
    }
}