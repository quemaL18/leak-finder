Инструмент для поиска чувствительных данных в файлах. Ищет email, JWT токены, UUID, номера карт, ключевые слова (password, token, secret, api_key и их русские аналоги). Сохраняет результаты в JSON.

как установить себе чз гит:

git clone https://github.com/quemaL18/leak-finder

cd leak-finder

cargo build --release

Использование

cargo run -- ./testdata --recursive --extensions txt,json --output report.json --verbose

Доступные параметры на 19.04: 

--level low/medium/high ( определяет количество и типы искомых паттернов: LOW ищет только самые критичные данные (email, credit card, JWT), MEDIUM добавляет основные паттерны и используется по умолчанию, а HIGH включает все возможные паттерны используемые в коде).

--recursive (-r) для рекурсивного обхода, 

--extensions для фильтра по расширениям (например txt,json), 

--output (-o) для сохранения результата, 

--verbose (-v) для подробного вывода, 

--max-size для ограничения размера файла.

Пример: cargo run -- ./testdata --recursive --output result.json --verbose

Вопросы в тг - @entr0p7
