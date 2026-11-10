//! Пример: проверка подключения к NVIDIA NIM с моделью Mistral Large 4.
//!
//! Загружает провайдеров и ключи из ~/.w420/ai_providers.db, строит KeyRotation
//! и отправляет тестовый chat-запрос. Ключ расшифровывается автоматически.
//!
//! Запуск:
//!   cargo run -p w420-ai --example test_nvidia

use w420_ai::db::AIProviderDB;
use w420_ai::rotation::KeyRotation;
use w420_ai::{ChatMessage, ChatRequest, ProviderType};

#[tokio::main]
async fn main() {
    let db = AIProviderDB::open().expect("БД не открылась");
    let rotation = KeyRotation::new();
    rotation.load_from_db(&db).await.expect("не удалось загрузить из БД");

    let providers = rotation.list_providers().await;
    println!("Провайдеров в БД: {}", providers.len());
    for p in &providers {
        println!("  - {} ({}), включён: {}, моделей: {}", p.name, p.provider_type, p.is_enabled, p.models.len());
    }

    let request = ChatRequest {
        model: "mistralai/mistral-large-4-1t-a52b".to_string(), // Mistral Large 4 на NVIDIA NIM
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "Ты — краткий ассистент. Отвечай одним предложением на русском.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: "Скажи 'W420 AI готов' если связь работает.".to_string(),
            },
        ],
        temperature: 0.2,
        max_tokens: Some(256),
        stream: false,
    };

    println!("\nОтправляю запрос к NVIDIA NIM (model={})...", request.model);
    let start = std::time::Instant::now();

    match rotation
        .chat_completion_with_rotation(request, Some(ProviderType::Nvidia))
        .await
    {
        Ok(resp) => {
            println!("✅ УСПЕХ за {:?}", start.elapsed());
            println!("  Провайдер: {} ({})", resp.provider_name, resp.provider_type);
            println!("  Ключ использован: {} (пробовано ключей: {})", resp.key_id, resp.keys_tried);
            println!("  Модель в ответе: {}", resp.response.model);
            println!("  Токенов: {:?}", resp.response.tokens_used);
            println!("  Ответ: {}", resp.response.content.trim());
        }
        Err(e) => {
            eprintln!("❌ ОШИБКА: {e}");
            std::process::exit(1);
        }
    }
}
