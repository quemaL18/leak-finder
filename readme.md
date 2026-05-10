# Leak Finder

Высокопроизводительный сканер утечек данных на Rust. Ищет ключи API, пароли, токены, email, номера карт, IP-адреса, телефоны и другие чувствительные данные.

## Установка

```bash
git clone https://github.com/quemaL18/leak-finder
cd leak-finder
cargo build --release
```

## Использование
leak-finder [ОПЦИИ] <ПУТЬ>
Опция	                            Описание
-r, --recursive	                  Рекурсивный обход

--extensions                      <список> Фильтр по расширениям (через запятую)

--max-size                        <байты>	Макс. размер файла (по умолч. 1_000_000)

-o, --output                      <файл>	JSON-отчёт

--html-report                     <файл>	HTML-отчёт

-v, --verbose	                    Подробный вывод

--level <low/medium/high>	        Уровень строгости (по умолч. medium)

--force	                          Игнорировать кэш

--clear-cache	                    Очистить кэш перед сканированием

--ignore-file                     <файл>	Пользовательский ignore-файл

--no-ignore	                      Отключить все ignore-правила

## Уровни поиска

Уровни поиска
Low (низкий), Лёгкая проверка - минимум ложных срабатываний. Подходит для быстрого прогона
    
  email - адреса электронной почты
    
  credit_card - номера кредитных карт (16 цифр с разделителями)
    
  jwt_token - JWT-токены (формат eyJ...)
    
Medium (средний, по умолчанию), Баланс между полнотой и количеством ложных срабатываний. Включает всё из Low, плюс:

  uuid - идентификаторы формата xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    
  password - слово "password" (регистронезависимо)
    
  token - слово "token"
    
  secret - слово "secret"
    
  api_key - слова "apikey" или "api_key"
    
  пароль - русское слово "пароль"
    
  токен - русское слово "токен"
    
  username - слово "username"
    
  generic_token - любая строка из 40+ букв и цифр
    
High (высокий), Максимальная строгость. Всё из Medium, плюс:

  phone - номера телефонов (10+ символов, включая +, пробелы, скобки, дефисы)
    
  ip_address - IPv4-адреса (формат xxx.xxx.xxx.xxx)

Каждый уровень включает предыдущий. Т.Е. --level high включает в себя (high, medium, low)

## Файл .scanignore
Файл .scanignore позволяет исключать файлы и директории из сканирования. Поддерживается синтаксис, аналогичный .gitignore. По умолчанию инструмент ищет этот файл в корне сканирования.
Пример .scanignore:
### Кэш и временные файлы
.cache/
*.tmp
*.swp

### Секреты отдельно (но не хотим случайно пропустить)
secrets/backup/
!secrets/readme.md

### Логи
logs/
*.log
!logs/important.log

### Артефакты сборки
target/
dist/
node_modules/

### Конфиги окружения (если нужно пропустить)
.env
*.local
## Пример использования
### Базовое сканирование
leak-finder ./src

### Рекурсивное сканирование с высоким уровнем
leak-finder -r ./project --level high

### С фильтром по расширениям и HTML-отчётом
leak-finder -r . --extensions rs,toml,json --html-report report.html

### Принудительное сканирование с сохранением JSON
leak-finder -r . --force --output result.json

### Очистить кэш и просканировать только txt-файлы
leak-finder . --extensions txt --clear-cache

### С кастомным ignore-файлом
leak-finder -r . --ignore-file ./custom_ignore.txt
