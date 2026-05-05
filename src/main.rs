use chrono::Local;
use clap::Parser;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
struct Args {
    path: PathBuf,

    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    #[arg(long)]
    extensions: Option<String>,

    #[arg(long, default_value_t = 1_000_000)]
    max_size: u64,

    #[arg(long, short)]
    output: Option<PathBuf>,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(long, default_value = "medium")]
    level: String,

    #[arg(long, default_value_t = false)]
    force: bool,

    #[arg(long, default_value_t = false)]
    clear_cache: bool,

    #[arg(long)]
    ignore_file: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    no_ignore: bool,

    #[arg(long)]
    html_report: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct MatchContext {
    pattern_name: String,
    line_number: usize,
    line_content: String,
    match_position: usize,
    match_length: usize,
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
    skipped_unchanged_files: i32,
    ignored_files: i32,
    warnings_count: i32,
    results: Vec<ScanResult>,
    verbose: bool,
    force: bool,
    scan_duration_ms: u128,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ScannerCache {
    files: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct FileCandidate {
    path: PathBuf,
    cache_key: String,
    hash: String,
}

fn get_patterns_by_level(level: &str) -> Vec<(String, Regex)> {
    let email = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    let jwt = Regex::new(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap();

    let uuid =
        Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
            .unwrap();

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
        "low" => vec![
            ("email".to_string(), email),
            ("credit_card".to_string(), credit_card),
            ("jwt_token".to_string(), jwt),
        ],

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

        _ => vec![
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
        ],
    }
}

fn get_scan_root(path: &Path) -> PathBuf {
    if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    }
}

fn normalize_cache_key(path: &Path, scan_root: &Path) -> String {
    let relative = path.strip_prefix(scan_root).unwrap_or(path);
    relative.to_string_lossy().replace('\\', "/")
}

fn calculate_sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn load_cache(cache_path: &Path, verbose: bool) -> ScannerCache {
    if !cache_path.exists() {
        return ScannerCache::default();
    }

    match fs::read_to_string(cache_path) {
        Ok(content) => match serde_json::from_str::<ScannerCache>(&content) {
            Ok(cache) => {
                if verbose {
                    println!("[ПОДРОБНО] Кэш загружен: {}", cache_path.display());
                }

                cache
            }

            Err(e) => {
                if verbose {
                    println!(
                        "[ПОДРОБНО] Не удалось разобрать кэш {}: {}",
                        cache_path.display(),
                        e
                    );
                }

                ScannerCache::default()
            }
        },

        Err(e) => {
            if verbose {
                println!(
                    "[ПОДРОБНО] Не удалось прочитать кэш {}: {}",
                    cache_path.display(),
                    e
                );
            }

            ScannerCache::default()
        }
    }
}

fn save_cache(cache_path: &Path, cache: &ScannerCache, verbose: bool) -> io::Result<()> {
    let json = serde_json::to_string_pretty(cache).unwrap();

    if let Some(parent) = cache_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    fs::write(cache_path, json)?;

    if verbose {
        println!("[ПОДРОБНО] Кэш сохранен: {}", cache_path.display());
    }

    Ok(())
}

fn build_ignore_matcher(
    scan_root: &Path,
    ignore_file: &Option<PathBuf>,
    no_ignore: bool,
    verbose: bool,
) -> Option<Gitignore> {
    if no_ignore {
        if verbose {
            println!("[ПОДРОБНО] Ignore-правила отключены через --no-ignore");
        }

        return None;
    }

    let mut builder = GitignoreBuilder::new(scan_root);

    for rule in [".git/", "target/", "node_modules/"] {
        if let Err(e) = builder.add_line(None, rule) {
            eprintln!(
                "[ОШИБКА] Не удалось добавить правило ignore '{}': {}",
                rule, e
            );
        }
    }

    let ignore_path = ignore_file
        .clone()
        .unwrap_or_else(|| scan_root.join(".scanignore"));

    if ignore_path.exists() {
        if let Some(error) = builder.add(&ignore_path) {
            eprintln!(
                "[ОШИБКА] Не удалось прочитать ignore-файл {}: {}",
                ignore_path.display(),
                error
            );
        } else if verbose {
            println!("[ПОДРОБНО] Ignore-файл подключен: {}", ignore_path.display());
        }
    } else if ignore_file.is_some() {
        eprintln!(
            "[ОШИБКА] Указанный ignore-файл не найден: {}",
            ignore_path.display()
        );
    }

    match builder.build() {
        Ok(matcher) => Some(matcher),

        Err(e) => {
            eprintln!("[ОШИБКА] Не удалось собрать ignore-правила: {}", e);
            None
        }
    }
}

fn is_ignored(
    path: &Path,
    scan_root: &Path,
    is_dir: bool,
    matcher: &Option<Gitignore>,
) -> bool {
    let Some(matcher) = matcher else {
        return false;
    };

    let relative = path.strip_prefix(scan_root).unwrap_or(path);

    matcher
        .matched_path_or_any_parents(relative, is_dir)
        .is_ignore()
}

fn is_internal_generated_file(path: &Path, cache_path: &Path, args: &Args) -> bool {
    if path == cache_path {
        return true;
    }

    if let Some(output) = &args.output {
        if path == output {
            return true;
        }
    }

    if let Some(html_report) = &args.html_report {
        if path == html_report {
            return true;
        }
    }

    false
}

fn scan_file(
    path: &PathBuf,
    patterns: &Arc<Vec<(String, Regex)>>,
    verbose: bool,
) -> Option<ScanResult> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let mut issues: Vec<String> = Vec::new();
            let mut contexts: Vec<MatchContext> = Vec::new();

            for (name, regex) in patterns.iter() {
                for (line_num, line) in content.lines().enumerate() {
                    if let Some(found_match) = regex.find(line) {
                        issues.push(name.clone());

                        contexts.push(MatchContext {
                            pattern_name: name.clone(),
                            line_number: line_num + 1,
                            line_content: line.to_string(),
                            match_position: found_match.start(),
                            match_length: found_match.end() - found_match.start(),
                        });

                        if verbose {
                            println!(
                                "[ПОДРОБНО] {}:{} - найден {}",
                                path.display(),
                                line_num + 1,
                                name
                            );
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

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn highlight_fragment(line: &str, start: usize, length: usize) -> String {
    let end = start.saturating_add(length);

    if start <= line.len() && end <= line.len() {
        format!(
            "{}<mark>{}</mark>{}",
            html_escape(&line[..start]),
            html_escape(&line[start..end]),
            html_escape(&line[end..])
        )
    } else {
        html_escape(line)
    }
}

fn generate_html_report(report: &ScanReport, output_path: &Path) -> io::Result<()> {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut pattern_names: BTreeSet<String> = BTreeSet::new();

    for result in &report.results {
        for context in &result.contexts {
            pattern_names.insert(context.pattern_name.clone());
        }
    }

    let mut options = String::from(r#"<option value="">Все типы</option>"#);

    for pattern in &pattern_names {
        options.push_str(&format!(
            r#"<option value="{}">{}</option>"#,
            html_escape(pattern),
            html_escape(pattern)
        ));
    }

    let mut rows = String::new();

    for result in &report.results {
        for context in &result.contexts {
            let highlighted_line = highlight_fragment(
                &context.line_content,
                context.match_position,
                context.match_length,
            );

            rows.push_str(&format!(
                r#"
<tr
    data-pattern="{pattern}"
    data-file="{file}"
    data-line="{line}"
>
    <td><span class="badge">{pattern}</span></td>
    <td><code>{file}</code></td>
    <td>{line}</td>
    <td><pre>{highlighted}</pre></td>
</tr>
"#,
                pattern = html_escape(&context.pattern_name),
                file = html_escape(&result.path),
                line = context.line_number,
                highlighted = highlighted_line
            ));
        }
    }

    if rows.is_empty() {
        rows.push_str(
            r#"
<tr>
    <td colspan="4" class="empty">Совпадений не найдено.</td>
</tr>
"#,
        );
    }

    let template = include_str!("report_template.html");

    let html = template
        .replace("{{timestamp}}", &html_escape(&report.timestamp))
        .replace("{{scan_path}}", &html_escape(&report.scan_path))
        .replace("{{recursive}}", &report.recursive.to_string())
        .replace("{{force}}", &report.force.to_string())
        .replace("{{total_files}}", &report.total_files.to_string())
        .replace("{{checked_files}}", &report.checked_files.to_string())
        .replace(
            "{{skipped_unchanged}}",
            &report.skipped_unchanged_files.to_string(),
        )
        .replace("{{ignored_files}}", &report.ignored_files.to_string())
        .replace("{{warnings_count}}", &report.warnings_count.to_string())
        .replace("{{options}}", &options)
        .replace("{{rows}}", &rows);

    fs::write(output_path, html)
}

fn main() {
    let args = Args::parse();
    let start_time = std::time::Instant::now();

    let scan_root = get_scan_root(&args.path);
    let cache_path = scan_root.join(".scanner_cache.json");

    if args.verbose {
        println!("[ПОДРОБНО] Запуск сканирования");
        println!("[ПОДРОБНО]   Путь: {}", args.path.display());
        println!("[ПОДРОБНО]   Корень сканирования: {}", scan_root.display());
        println!("[ПОДРОБНО]   Рекурсивно: {}", args.recursive);
        println!("[ПОДРОБНО]   Макс. размер: {} байт", args.max_size);
        println!("[ПОДРОБНО]   Уровень: {}", args.level);
        println!("[ПОДРОБНО]   Force: {}", args.force);
        println!("[ПОДРОБНО]   No ignore: {}", args.no_ignore);

        if let Some(output) = &args.output {
            println!("[ПОДРОБНО]   JSON-вывод: {}", output.display());
        }

        if let Some(html_report) = &args.html_report {
            println!("[ПОДРОБНО]   HTML-отчет: {}", html_report.display());
        }
    }

    if args.clear_cache && cache_path.exists() {
        match fs::remove_file(&cache_path) {
            Ok(_) => {
                if args.verbose {
                    println!("[ПОДРОБНО] Кэш очищен: {}", cache_path.display());
                }
            }

            Err(e) => {
                eprintln!(
                    "[ОШИБКА] Не удалось очистить кэш {}: {}",
                    cache_path.display(),
                    e
                );
            }
        }
    }

    let mut cache = load_cache(&cache_path, args.verbose);

    let ignore_matcher = build_ignore_matcher(
        &scan_root,
        &args.ignore_file,
        args.no_ignore,
        args.verbose,
    );

    let extensions: Option<Vec<String>> = args.extensions.as_ref().map(|ext| {
        ext.split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    });

    let mut files_to_scan: Vec<FileCandidate> = Vec::new();
    let mut current_cache_keys: HashSet<String> = HashSet::new();

    let mut total_files: i32 = 0;
    let mut skipped_large_files: i32 = 0;
    let mut skipped_unchanged_files: i32 = 0;
    let mut ignored_files: i32 = 0;

    let walker = if !args.recursive || args.path.is_file() {
        WalkDir::new(&args.path).max_depth(1)
    } else {
        WalkDir::new(&args.path)
    };

    for entry in walker.into_iter() {
        match entry {
            Ok(entry) => {
                let path = entry.path().to_path_buf();
                let is_dir = entry.file_type().is_dir();

                if is_ignored(&path, &scan_root, is_dir, &ignore_matcher) {
                    if entry.file_type().is_file() {
                        ignored_files += 1;
                    }

                    if args.verbose {
                        println!("[ПОДРОБНО] Исключено по правилам: {}", path.display());
                    }

                    continue;
                }

                if !entry.file_type().is_file() {
                    continue;
                }

                if is_internal_generated_file(&path, &cache_path, &args) {
                    continue;
                }

                total_files += 1;

                if let Some(exts) = &extensions {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if !exts.contains(&ext.to_lowercase()) {
                            if args.verbose {
                                println!(
                                    "[ПОДРОБНО] Пропущен (расширение): {}",
                                    path.display()
                                );
                            }

                            continue;
                        }
                    } else {
                        if args.verbose {
                            println!(
                                "[ПОДРОБНО] Пропущен (нет расширения): {}",
                                path.display()
                            );
                        }

                        continue;
                    }
                }

                match fs::metadata(&path) {
                    Ok(metadata) => {
                        if metadata.len() > args.max_size {
                            skipped_large_files += 1;

                            if args.verbose {
                                println!(
                                    "[ПОДРОБНО] Пропущен (большой): {} ({} байт)",
                                    path.display(),
                                    metadata.len()
                                );
                            }

                            continue;
                        }
                    }

                    Err(e) => {
                        println!(
                            "[ОШИБКА] Не удалось получить метаданные {}: {}",
                            path.display(),
                            e
                        );

                        continue;
                    }
                }

                let hash = match calculate_sha256(&path) {
                    Ok(hash) => hash,

                    Err(e) => {
                        println!(
                            "[ОШИБКА] Не удалось посчитать SHA-256 для {}: {}",
                            path.display(),
                            e
                        );

                        continue;
                    }
                };

                let cache_key = normalize_cache_key(&path, &scan_root);

                current_cache_keys.insert(cache_key.clone());

                let unchanged = cache
                    .files
                    .get(&cache_key)
                    .map(|old_hash| old_hash == &hash)
                    .unwrap_or(false);

                if unchanged && !args.force {
                    skipped_unchanged_files += 1;

                    if args.verbose {
                        println!(
                            "[ПОДРОБНО] Пропущен (не изменился): {}",
                            path.display()
                        );
                    }

                    continue;
                }

                files_to_scan.push(FileCandidate {
                    path,
                    cache_key,
                    hash,
                });
            }

            Err(e) => {
                println!("[ОШИБКА] Доступ к элементу: {}", e);
            }
        }
    }

    let patterns = Arc::new(get_patterns_by_level(&args.level));

    let results: Vec<ScanResult> = files_to_scan
        .par_iter()
        .filter_map(|file| scan_file(&file.path, &patterns, args.verbose))
        .collect();

    for file in &files_to_scan {
        cache.files.insert(file.cache_key.clone(), file.hash.clone());
    }

    cache
        .files
        .retain(|cache_key, _| current_cache_keys.contains(cache_key));

    if let Err(e) = save_cache(&cache_path, &cache, args.verbose) {
        eprintln!(
            "[ОШИБКА] Не удалось сохранить кэш {}: {}",
            cache_path.display(),
            e
        );
    }

    let checked_files = files_to_scan.len() as i32;
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
        skipped_unchanged_files,
        ignored_files,
        warnings_count,
        results,
        verbose: args.verbose,
        force: args.force,
        scan_duration_ms: duration,
    };

    if let Some(output_path) = &args.output {
        let json = serde_json::to_string_pretty(&report).unwrap();

        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = fs::create_dir_all(parent) {
                    eprintln!(
                        "[ОШИБКА] Не удалось создать директорию {}: {}",
                        parent.display(),
                        e
                    );
                }
            }
        }

        match fs::write(output_path, json) {
            Ok(_) => println!("Результаты сохранены: {}", output_path.display()),

            Err(e) => eprintln!(
                "[ОШИБКА] Не удалось сохранить JSON-отчет {}: {}",
                output_path.display(),
                e
            ),
        }
    }

    if let Some(html_report_path) = &args.html_report {
        match generate_html_report(&report, html_report_path) {
            Ok(_) => println!("HTML-отчет сохранен: {}", html_report_path.display()),

            Err(e) => eprintln!(
                "[ОШИБКА] Не удалось сохранить HTML-отчет {}: {}",
                html_report_path.display(),
                e
            ),
        }
    }

    if args.output.is_none() {
        println!("\nНайденные проблемы:");

        if report.results.is_empty() {
            println!("Совпадений не найдено.");
        } else {
            for result in &report.results {
                println!("\nФайл: {}", result.path);

                for context in &result.contexts {
                    println!(
                        "  [{}] Строка {}: {}",
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
        println!(
            "  Пропущено (не изменились): {} файлов",
            skipped_unchanged_files
        );
        println!("  Предупреждений: {}", warnings_count);
        println!("  Уровень: {}", args.level);
    }

    if args.verbose {
        println!(
            "[ПОДРОБНО] Исключено по правилам: {} файлов",
            ignored_files
        );
    }
}