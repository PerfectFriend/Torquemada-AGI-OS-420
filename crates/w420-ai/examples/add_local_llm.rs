//! Добавляет локальный LLM (llama.cpp на Vulkan, http://127.0.0.1:8081/v1)
//! в ~/.w420/ai_providers.db как провайдера типа Custom (OpenAI-совместимый),
//! с фиктивным ключом (сервер Authorization игнорирует), и сразу проверяет
//! chat end-to-end через KeyRotation — тот же путь, что используют ai_chat/ai_soc.
//!
//! Запуск: source ~/build/env.sh && cd ~/TorquemadaAGI && cargo run -p w420-ai --example add_local_llm
use w420_ai::db::AIProviderDB;
use w420_ai::encryption::encrypt_api_key;
use w420_ai::rotation::KeyRotation;
use w420_ai::{ChatMessage, ChatRequest, ProviderConfig, ProviderKeyConfig, ProviderType};

#[tokio::main]
async fn main() {
    let endpoint = "http://127.0.0.1:8081/v1".to_string();
    let model = "deepseek-coder-6.7b-q4km".to_string();

    let db = AIProviderDB::open().expect("open ai_providers.db");

    // Идемпотентность: если провайдер с таким именем уже есть — не дублируем.
    let existing = db.list_providers().unwrap_or_default();
    let local = existing.iter().find(|p| p.name == "Local llama.cpp (Vulkan)");
    let provider_id = match local {
        Some(p) => {
            println!("провайдер уже есть: {} ({})", p.name, p.id);
            p.id.clone()
        }
        None => {
            let cfg = ProviderConfig {
                id: format!("prov-{}", uuid::Uuid::new_v4()),
                provider_type: ProviderType::Custom,
                name: "Local llama.cpp (Vulkan)".to_string(),
                endpoint: endpoint.clone(),
                models: vec![model.clone()],
                is_enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            db.add_provider(&cfg).expect("add_provider");
            println!("провайдер добавлен: {} -> {}", cfg.name, cfg.endpoint);
            cfg.id
        }
    };

    // Фиктивный ключ (мин. 8 символов по правилу ai_provider_add_key); llama.cpp его игнорирует.
    let keys = db.list_keys_for_provider(&provider_id).unwrap_or_default();
    if keys.iter().all(|k| !k.is_active) {
        let encrypted = encrypt_api_key("local-no-auth").expect("encrypt");
        let kc = ProviderKeyConfig {
            id: format!("key-{}", uuid::Uuid::new_v4()),
            provider_id: provider_id.clone(),
            nickname: Some("local (no auth)".to_string()),
            encrypted_key: encrypted,
            is_active: true,
            last_tested: None,
            avg_latency_ms: None,
            error_count: 0,
            blocked_until: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        db.add_key(&kc).expect("add_key");
        println!("ключ добавлен: {}", kc.id);
    }

    // End-to-end: тот же путь, что ai_chat — ротация по всем провайдерам/ключам.
    let providers = db.list_providers().expect("list_providers");
    let all_keys = db.list_all_keys().expect("list_all_keys");
    let rotation = KeyRotation::new();
    for p in providers {
        rotation.add_provider(p).await;
    }
    for k in all_keys.into_iter().filter(|k| k.is_active) {
        rotation.add_key(k).await;
    }
    let req = ChatRequest {
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Ответь одним словом: РАБОТАЕТ".to_string(),
        }],
        model,
        temperature: 0.0,
        max_tokens: Some(16),
        stream: false,
    };
    match rotation
        .chat_completion_with_rotation(req, Some(ProviderType::Custom))
        .await
    {
        Ok(r) => println!(
            "E2E OK: provider={} model={} key={} latency={}ms tokens={:?} text={:?}",
            r.provider_name, r.response.model, r.key_id, r.response.latency_ms, r.response.tokens_used, r.response.content
        ),
        Err(e) => {
            println!("E2E FAIL: {e}");
            std::process::exit(1);
        }
    }
}
