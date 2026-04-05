Инструмент для поиска чувствительных данных в файлах. Ищет email, JWT токены, UUID, номера карт, ключевые слова (password, token, secret, api_key и их русские аналоги). Сохраняет результаты в JSON.

как установить себе: 
git clone https://github.com/quemaL18/leak-finder

cd leak-finder

cargo build --release

Использование

cargo run -- ./testdata --recursive --extensions txt,json --output report.json --verbose

Доступные параметры на 05.04: --recursive (-r) для рекурсивного обхода, --extensions для фильтра по расширениям (например txt,json), --output (-o) для сохранения результата, --verbose (-v) для подробного вывода, --max-size для ограничения размера файла.

Пример: cargo run -- ./testdata --recursive --output result.json --verbose

Вопросы в тг - @entr0p7
