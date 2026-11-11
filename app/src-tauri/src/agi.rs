//! agi.rs — AI-мост AGI-оболочки (Этап 19 плана эволюции).
//!
//! Чат оболочки (AGI-Ω), whitelist-инструменты для модели и автономные задачи
//! с human-in-the-loop. Вся работа с ключами провайдеров — внутри
//! `ai_providers::chat_messages` (KeyRotation), сюда ключи не попадают.

use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::Duration;
use w420_ai::ChatMessage;

use crate::ai_providers;

/// Системный промпт AGI-оболочки W420.
pub const AGI_SYSTEM_PROMPT: &str = "Ты — AGI-Ω, встроенный ИИ-ассистент security-платформы W420 \
(брандмауэр nftables, SIEM, EDR, VPN, сканеры, PKI, AI SOC). Отвечай по-русски, кратко и по делу. \
У тебя есть инструменты чтения состояния (agi_tools_list); используй их факты, не выдумывай. \
Если нужно изменить данные системы — предложи действие в формате PROPOSE: {\"kind\":\"run_tool\",\"params\":{\"tool\":\"имя\",\"args\":{}}}} \
отдельной строкой; пользователь подтвердит вручную.";

// ============================================================================
// Инструменты (whitelist — только чтение состояния, никаких мутаций)
// ============================================================================

/// Список инструментов, доступных модели. Только чтение — запись через PROPOSE+approve.
pub fn tools_list() -> Vec<Value> {
    vec![
        json!({"name": "system_status", "description": "CPU/RAM/OS/host живой машины (sysinfo)"}),
        json!({"name": "siem_dashboard", "description": "Сводка SIEM: события, инциденты, топ источников"}),
        json!({"name": "soc_status", "description": "Статус AI SOC: playbooks, последние циклы, инциденты"}),
        json!({"name": "threats_last_scan", "description": "Результат последнего сканирования угроз (CVE)"}),
        json!({"name": "madre_helm", "description": "Штурвал Матери Торквемады: промпт арсенала, режим, allowlist, свежие события (read-only)"}),
        json!({"name": "madre_status", "description": "Статус арсенала Матери: honeypot/watchdog, конфиг, события (read-only)"}),
    ]
}

/// Whitelist: инструмент можно выполнить автоматически после approve.
pub fn whitelisted_tool(name: &str) -> bool {
    tools_list()
        .iter()
        .any(|t| t["name"].as_str() == Some(name))
}

/// Выполнение инструмента (только чтение состояния системы).
pub async fn tool_exec(
    name: &str,
    _args: &Value,
    siem: &crate::siem::SiemManager,
    soc: &crate::ai_soc::SocManager,
    threats: &crate::threats::ThreatMonitor,
    madre: &crate::madre::MadreManager,
) -> Result<Value, String> {
    if !whitelisted_tool(name) {
        return Err(format!("инструмент не в whitelist: {name}"));
    }
    match name {
        "system_status" => {
            // Свежий срез метрик напрямую из sysinfo (state в lib.rs — отдельный экземпляр)
            let mut s = sysinfo::System::new_all();
            s.refresh_cpu();
            s.refresh_memory();
            Ok(json!({
                "cpu": s.global_cpu_info().cpu_usage(),
                "cores": s.cpus().len(),
                "mem_used": s.used_memory(),
                "mem_total": s.total_memory(),
                "uptime": sysinfo::System::uptime(),
                "os": sysinfo::System::long_os_version().unwrap_or_default(),
                "host": sysinfo::System::host_name().unwrap_or_default(),
            }))
        }
        "siem_dashboard" => siem.dashboard(),
        "soc_status" => soc.status(),
        "threats_last_scan" => Ok(json!(threats.last_scan_result())),
        "madre_helm" => Ok(crate::madre::helm_value(madre)),
        "madre_status" => Ok(crate::madre::status_value(madre)),
        _ => Err("неизвестный инструмент".to_string()),
    }
}

// ============================================================================
// Автономная задача (human-in-the-loop)
// ============================================================================

/// Предложение действия от модели, ждущее подтверждения пользователя.
#[derive(Clone, Serialize)]
pub struct Proposal {
    pub id: u64,
    pub kind: String,
    pub params: Value,
    /// pending | approved | rejected | executed | failed
    pub status: String,
}

/// Состояние автономной задачи.
#[derive(Default)]
pub struct TaskState {
    pub running: bool,
    pub goal: String,
    pub n: u32,
    pub max: u32,
    pub interval_secs: u64,
    pub notes: Vec<String>,
    pub proposals: Vec<Proposal>,
    pub next_id: u64,
    pub handle: Option<tokio::task::JoinHandle<()>>,
}

/// Менеджер AGI-оболочки: состояние автономной задачи.
pub struct Agi(pub Mutex<TaskState>);

/// Разбор ответа модели задачи: строки `PROPOSE: {json}` → предложения,
/// остальные непустые строки → заметки-отчёты.
pub fn parse_task_reply(text: &str) -> (Vec<String>, Vec<(String, Value)>) {
    let mut notes = Vec::new();
    let mut props = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("PROPOSE:") {
            if let Ok(v) = serde_json::from_str::<Value>(rest.trim()) {
                let kind = v["kind"].as_str().unwrap_or("note").to_string();
                props.push((kind, v.get("params").cloned().unwrap_or(json!({}))));
                continue;
            }
        }
        notes.push(line.to_string());
    }
    (notes, props)
}

/// Промпт одного тика автономной задачи.
pub fn build_task_prompt(goal: &str, notes: &[String], n: u32, max: u32) -> String {
    let prev = notes.iter().rev().take(3).cloned().collect::<Vec<_>>().join(" | ");
    format!(
        "Автономная задача: «{goal}». Запуск {n} из {max}. Предыдущие заметки: {prev}. \
         Вызови нужные инструменты (system_status, siem_dashboard, soc_status, threats_last_scan) мысленно по фактам. \
         Ответь ОДНОЙ короткой строкой-отчётом (до 160 символов). \
         Если нужно изменить данные — добавь строку PROPOSE: {{\"kind\":\"run_tool\",\"params\":{{\"tool\":\"…\",\"args\":{{}}}}}}."
    )
}

impl Agi {
    pub fn push_proposal(&self, kind: String, params: Value) -> Proposal {
        let mut st = self.0.lock().unwrap();
        st.next_id += 1;
        let p = Proposal {
            id: st.next_id,
            kind,
            params,
            status: "pending".to_string(),
        };
        st.proposals.push(p.clone());
        p
    }

    /// Одобрить/отклонить предложение. kind="run_tool" с whitelisted инструментом выполняется.
    pub async fn decide(
        &self,
        id: u64,
        approve: bool,
        siem: &crate::siem::SiemManager,
        soc: &crate::ai_soc::SocManager,
        threats: &crate::threats::ThreatMonitor,
        madre: &crate::madre::MadreManager,
    ) -> Result<Proposal, String> {
        // 1) Меняем статус под lock, параметры забираем — guard ДО .await дропаем (MutexGuard !Send).
        let (kind, params) = {
            let mut st = self.0.lock().unwrap();
            let p = st
                .proposals
                .iter_mut()
                .find(|p| p.id == id && p.status == "pending")
                .ok_or_else(|| format!("proposal {id} не найден или уже решён"))?;
            p.status = if approve { "approved" } else { "rejected" }.to_string();
            (p.kind.clone(), p.params.clone())
        };
        // 2) Выполняем whitelisted чтение БЕЗ удержания lock (async под guard нельзя).
        let exec = if approve && kind == "run_tool" {
            let tool = params["tool"].as_str().unwrap_or("");
            let args = params.get("args").cloned().unwrap_or(json!({}));
            Some(tool_exec(tool, &args, siem, soc, threats, madre).await)
        } else {
            None
        };
        // 3) Финальный статус записываем после await.
        let mut st = self.0.lock().unwrap();
        let p = st.proposals.iter_mut().find(|p| p.id == id).unwrap();
        if let Some(r) = exec {
            match r {
                Ok(_) => p.status = "executed".to_string(),
                Err(e) => {
                    p.status = "failed".to_string();
                    p.params = json!({"error": e});
                }
            }
        }
        Ok(p.clone())
    }
}

// ============================================================================
// Tauri-команды
// ============================================================================

/// Доступен ли AI (есть ли включённый провайдер с ключами) — для бейджа LIVE/SIM.
#[tauri::command]
pub fn agi_status() -> Result<Value, String> {
    let db = w420_ai::db::AIProviderDB::open().map_err(|e| e.to_string())?;
    let providers = db.list_providers().map_err(|e| e.to_string())?;
    let keys = db.list_all_keys().map_err(|e| e.to_string())?;
    let available = providers.iter().any(|p| p.is_enabled)
        && keys.iter().any(|k| k.is_active);
    Ok(json!({"available": available, "providers": providers.len(), "active_keys": keys.iter().filter(|k| k.is_active).count()}))
}

/// Одна реплика чата AGI-Ω с историей. История приходит из фронтенда (w420.hist).
#[derive(serde::Deserialize)]
pub struct HistMsg {
    role: String,
    content: String,
}

/// Чат AGI-Ω: системный промпт + история + вопрос → ответ через ротацию ключей.
#[tauri::command]
pub async fn agi_chat(prompt: String, history: Option<Vec<HistMsg>>) -> Result<Value, String> {
    let mut messages = vec![ChatMessage {
        role: "system".to_string(),
        content: AGI_SYSTEM_PROMPT.to_string(),
    }];
    for h in history.unwrap_or_default().into_iter().take(20) {
        let role = if h.role == "assistant" { "assistant" } else { "user" };
        messages.push(ChatMessage {
            role: role.to_string(),
            content: h.content,
        });
    }
    messages.push(ChatMessage {
        role: "user".to_string(),
        content: prompt,
    });
    let out = ai_providers::chat_messages(messages, None, None).await?;
    Ok(json!({
        "text": out.text, "model": out.model, "provider": out.provider_name,
        "key_mask": out.key_mask, "keys_tried": out.keys_tried,
        "tokens_used": out.tokens_used, "latency_ms": out.latency_ms,
    }))
}

/// Список инструментов модели.
#[tauri::command]
pub fn agi_tools_list() -> Vec<Value> {
    tools_list()
}

/// Ручное выполнение инструмента из UI (read-only whitelist).
#[tauri::command]
pub async fn agi_tool_exec(
    name: String,
    args: Option<Value>,
    siem: tauri::State<'_, crate::siem::SiemManager>,
    soc: tauri::State<'_, crate::ai_soc::SocManager>,
    threats: tauri::State<'_, crate::threats::ThreatMonitor>,
    madre: tauri::State<'_, crate::madre::MadreManager>,
) -> Result<Value, String> {
    tool_exec(&name, &args.unwrap_or(json!({})), &siem, &soc, &threats, &madre).await
}

/// Старт автономной задачи: выставляет состояние и спавнит цикл опросов модели.
#[tauri::command]
pub fn task_start(goal: String, interval_secs: Option<u64>, max: Option<u32>) -> Result<Value, String> {
    let agi = agi_arc();
    let mut st = agi.0.lock().unwrap();
    if st.running {
        return Err("задача уже выполняется".to_string());
    }
    if goal.trim().is_empty() {
        return Err("нужна цель задачи".to_string());
    }
    st.running = true;
    st.goal = goal.trim().to_string();
    st.n = 0;
    st.max = max.unwrap_or(10);
    st.interval_secs = interval_secs.unwrap_or(60).max(5);
    st.notes.clear();
    st.proposals.clear();
    let out = json!({"started": true, "goal": st.goal, "interval_secs": st.interval_secs, "max": st.max});
    if st.handle.is_none() {
        let a = agi.clone();
        st.handle = Some(tokio::spawn(async move { task_loop(a).await }));
    }
    Ok(out)
}

/// Внутренний цикл задачи — вызывается из spawn'нутой tokio-задачи.
pub async fn task_loop(agi: std::sync::Arc<Agi>) {
    loop {
        let (goal, n, max, interval, running) = {
            let st = agi.0.lock().unwrap();
            (st.goal.clone(), st.n, st.max, st.interval_secs, st.running)
        };
        if !running || n >= max {
            let mut st = agi.0.lock().unwrap();
            st.running = false;
            st.notes.push("задача завершена".to_string());
            return;
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let prompt = {
            let st = agi.0.lock().unwrap();
            build_task_prompt(&st.goal, &st.notes, st.n + 1, st.max)
        };
        let msgs = vec![
            ChatMessage { role: "system".to_string(), content: AGI_SYSTEM_PROMPT.to_string() },
            ChatMessage { role: "user".to_string(), content: prompt },
        ];
        match ai_providers::chat_messages(msgs, None, None).await {
            Ok(out) => {
                let (notes, props) = parse_task_reply(&out.text);
                let mut st = agi.0.lock().unwrap();
                st.n += 1;
                for note in notes {
                    st.notes.push(note);
                }
                drop(st);
                for (kind, params) in props {
                    agi.push_proposal(kind, params);
                }
            }
            Err(e) => {
                let mut st = agi.0.lock().unwrap();
                st.n += 1;
                st.notes.push(format!("ошибка модели: {e}"));
            }
        }
    }
}

/// Стоп задачи.
#[tauri::command]
pub fn task_stop() -> Result<Value, String> {
    let agi = agi_arc();
    let mut st = agi.0.lock().unwrap();
    st.running = false;
    if let Some(h) = st.handle.take() {
        h.abort();
    }
    Ok(json!({"stopped": true, "n": st.n, "notes": st.notes}))
}

/// Статус задачи: заметки + pending-предложения для UI.
#[tauri::command]
pub fn task_status() -> Result<Value, String> {
    let agi = agi_arc();
    let st = agi.0.lock().unwrap();
    Ok(json!({
        "running": st.running, "goal": st.goal, "n": st.n, "max": st.max,
        "interval_secs": st.interval_secs,
        "notes": st.notes.iter().rev().take(10).cloned().collect::<Vec<_>>(),
        "pending": st.proposals.iter().filter(|p| p.status == "pending").cloned().collect::<Vec<_>>(),
        "history": st.proposals.iter().rev().take(10).cloned().collect::<Vec<_>>(),
    }))
}

/// Подтверждение/отклонение предложения модели.
#[tauri::command]
pub async fn task_approve(
    id: u64,
    approve: bool,
    siem: tauri::State<'_, crate::siem::SiemManager>,
    soc: tauri::State<'_, crate::ai_soc::SocManager>,
    threats: tauri::State<'_, crate::threats::ThreatMonitor>,
    madre: tauri::State<'_, crate::madre::MadreManager>,
) -> Result<Proposal, String> {
    agi_arc().decide(id, approve, &siem, &soc, &threats, &madre).await
}

static AGI_ARC: std::sync::OnceLock<std::sync::Arc<Agi>> = std::sync::OnceLock::new();
fn agi_arc() -> std::sync::Arc<Agi> {
    AGI_ARC
        .get_or_init(|| std::sync::Arc::new(Agi(Mutex::new(TaskState::default()))))
        .clone()
}

// ============================================================================
// Тесты
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_task_reply_notes_and_proposals() {
        let text = "Сканирую сеть…\nPROPOSE: {\"kind\":\"run_tool\",\"params\":{\"tool\":\"siem_dashboard\",\"args\":{}}}\nВсё тихо.";
        let (notes, props) = parse_task_reply(text);
        assert_eq!(notes, vec!["Сканирую сеть…", "Всё тихо."]);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].0, "run_tool");
        assert_eq!(props[0].1["tool"], "siem_dashboard");
    }

    #[test]
    fn test_parse_task_reply_empty_and_bad_propose() {
        let (notes, props) = parse_task_reply("\nPROPOSE: не-json\nок");
        assert_eq!(notes, vec!["PROPOSE: не-json", "ок"]);
        assert!(props.is_empty());
    }

    #[test]
    fn test_build_task_prompt_contains_goal() {
        let p = build_task_prompt("следи за сетью", &["a".into()], 2, 10);
        assert!(p.contains("следи за сетью"));
        assert!(p.contains("2 из 10"));
    }

    #[test]
    fn test_whitelist() {
        assert!(whitelisted_tool("system_status"));
        assert!(whitelisted_tool("siem_dashboard"));
        assert!(whitelisted_tool("madre_helm"));
        assert!(whitelisted_tool("madre_status"));
        assert!(!whitelisted_tool("fw_isolate_host")); // мутации — только вручную
        assert!(!whitelisted_tool("madre_apply")); // применение правил — только руками
        assert!(!whitelisted_tool("rm"));
        assert_eq!(tools_list().len(), 6);
    }

    #[test]
    fn test_task_state_proposal_flow() {
        let agi = Agi(Mutex::new(TaskState::default()));
        let p = agi.push_proposal("note".into(), json!({"text": "привет"}));
        assert_eq!(p.id, 1);
        assert_eq!(p.status, "pending");
        // Без менеджеров тут не проверить decide (нужны State), но постановка/поиск — ок:
        let st = agi.0.lock().unwrap();
        assert_eq!(st.proposals.len(), 1);
        assert_eq!(st.proposals[0].kind, "note");
    }
}
