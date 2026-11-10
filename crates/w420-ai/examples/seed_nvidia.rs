//! Пример: начальное наполнение БД w420-ai провайдером NVIDIA NIM и его API-ключами.
//!
//! Ключи читаются из файла хранилища Obsidian (LLM-API-KEYS.md) и сохраняются
//! в ~/.w420/ai_providers.db в зашифрованном виде (AES-256-GCM через encrypt_api_key).
//!
//! Запуск:
//!   cargo run -p w420-ai --example seed_nvidia
//!
//! Модель по умолчанию: Mistral Large 4 (mistralai/mistral-large-4-1t-a52b) на NVIDIA NIM.

use w420_ai::db::AIProviderDB;
use w420_ai::encryption::encrypt_api_key;
use w420_ai::{ProviderConfig, ProviderKeyConfig, ProviderType};
use chrono::Utc;
use uuid::Uuid;

/// Путь к файлу с ключами в хранилище Obsidian.
const KEYS_FILE: &str = "/home/thomas/Документы/ObsidianVault/LLM-API-KEYS.md";

/// Модели NVIDIA NIM, которые будем использовать (по умолчанию — Mistral Large 4).
const DEFAULT_MODELS: &[&str] = &[
    "mistralai/mistral-large-4-1t-a52b", // Mistral Large 4 — модель по умолчанию
    "mistralai/mistral-large-2411",
    "meta/llama-3.1-405b-instruct",
    "meta/llama-3.1-70b-instruct",
    "qwen/qwen2.5-72b-instruct",
];

fn main() {
    // 1. Читаем ключи из файла хранилища
    let content = std::fs::read_to_string(KEYS_FILE)
        .unwrap_or_else(|e| panic!("не удалось прочитать {KEYS_FILE}: {e}"));

    // Извлекаем все строки, начинающиеся с "nvapi-" — это NVIDIA ключи
    let keys: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("nvapi-"))
        .map(|s| s.to_string())
        .collect();

    println!("Найдено {} NVIDIA ключей в {}", keys.len(), KEYS_FILE);
    assert!(!keys.is_empty(), "не найдено ни одного nvapi- ключа");

    // 2. Открываем БД провайдеров (создастся ~/.w420/ai_providers.db)
    let db = AIProviderDB::open().expect("не удалось открыть БД провайдеров");
    println!("БД открыта: {:?}", db.db_path());

    // 3. Проверяем, не добавлен ли уже провайдер NVIDIA — если да, удаляем (идемпотентность)
    let existing = db.list_providers().unwrap_or_default();
    for p in &existing {
        if p.provider_type == ProviderType::Nvidia {
            println!("Удаляю существующий провайдер NVIDIA: {} ({})", p.name, p.id);
            db.remove_provider(&p.id).expect("не удалось удалить старый провайдер");
        }
    }

    // 4. Создаём провайдера NVIDIA NIM
    let provider = ProviderConfig {
        id: Uuid::new_v4().to_string(),
        provider_type: ProviderType::Nvidia,
        name: "NVIDIA NIM (default)".to_string(),
        endpoint: "https://integrate.api.nvidia.com/v1".to_string(),
        models: DEFAULT_MODELS.iter().map(|s| s.to_string()).collect(),
        is_enabled: true,
        created_at: Utc::now().to_rfc3339(),
    };

    db.add_provider(&provider).expect("не удалось добавить провайдера");
    println!("Провайдер добавлен: {} ({})", provider.name, provider.id);
    println!("  endpoint: {}", provider.endpoint);
    println!("  модели: {:?}", provider.models);

    // 5. Добавляем каждый ключ в зашифрованном виде
    let now = Utc::now().to_rfc3339();
    let mut added = 0;
    for (i, key) in keys.iter().enumerate() {
        // Шифруем ключ перед сохранением — в БД хранится только ciphertext
        let encrypted = encrypt_api_key(key).expect("не удалось зашифровать ключ");

        let key_config = ProviderKeyConfig {
            id: Uuid::new_v4().to_string(),
            provider_id: provider.id.clone(),
            nickname: Some(format!("nvidia-key-{}", i + 1)),
            encrypted_key: encrypted,
            is_active: true,
            last_tested: None,
            avg_latency_ms: None,
            error_count: 0,
            blocked_until: None,
            created_at: now.clone(),
        };

        db.add_key(&key_config).expect("не удалось добавить ключ");
        added += 1;
        // Не печатаем сам ключ, только никнейм
        println!("  ключ #{} добавлен (зашифрован, id={})", i + 1, key_config.id);
    }

    println!("\n✅ Готово: провайдер NVIDIA NIM + {} ключей добавлены в {:?}", added, db.db_path());
    println!("   Модель по умолчанию: {}", DEFAULT_MODELS[0]);
    println!("   Ключи хранятся в зашифрованном виде (AES-256-GCM), расшифровка — при запросе.");

    // 6. Проверка: читаем обратно и убеждаемся, что ключи на месте и не в plaintext
    let providers = db.list_providers().unwrap();
    let nvidia = providers.iter().find(|p| p.provider_type == ProviderType::Nvidia)
        .expect("провайдер NVIDIA не найден после добавления");
    let keys_back = db.list_keys_for_provider(&nvidia.id).unwrap();
    println!("\nПроверка: в БД {} провайдер(ов), у NVIDIA {} ключей", providers.len(), keys_back.len());
    for k in &keys_back {
        assert!(!k.encrypted_key.starts_with("nvapi-"), "ключ хранится в открытом виде!");
    }
    println!("Проверка пройдена: все ключи в БД зашифрованы (не plaintext).");
}
