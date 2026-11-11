use serde::Serialize;
use std::sync::Mutex;
use sysinfo::System;
use tauri::Manager;

mod bridge;
mod tor;
mod sysops;
mod hosts;
mod threats;
mod security_ai;
mod net_scan;
mod traffic;
mod settings;
mod ai_providers;
mod emergency;
mod voice;
mod updates;
mod harden;
mod firewall;
mod siem;
mod edr;
mod patch_mgmt;
mod vpn;
mod web_scan;
mod pki;
mod ai_soc;
mod agi;
mod wallet;
mod pqc;
mod did;
mod radio;
mod map;
mod rdesk;
mod rat;
mod argus;
mod netutil;
mod ad;
mod sessrec;
mod smartcard;
mod reg;
mod evtlog;
mod taskext;
mod fmgr;
mod madre;
mod health;

struct Sys(Mutex<System>);

/// Local XTTS engine process: (child, token, port).
struct TtsProc(Mutex<Option<(std::process::Child, String, u16)>>);

#[derive(Serialize)]
struct TtsInfo {
    port: u16,
    token: String,
}

fn make_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    (0..4u64)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(i);
            format!("{:016x}", h.finish())
        })
        .collect()
}

/// Starts (or reuses) the local XTTS engine described in ~/.w420/tts.json (written by the installer).
/// The license flag is passed on only when the user has ticked the CPML checkbox in the UI.
#[tauri::command]
fn tts_start(
    app: tauri::AppHandle,
    state: tauri::State<TtsProc>,
    accept_license: bool,
) -> Result<TtsInfo, String> {
    let mut guard = state.0.lock().map_err(|_| "внутренняя ошибка")?;
    if let Some((child, token, port)) = guard.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(TtsInfo { port: *port, token: token.clone() });
        }
    }
    let home = app.path().home_dir().map_err(|e| e.to_string())?.join(".w420");
    let cfg: serde_json::Value = std::fs::read_to_string(home.join("tts.json"))
        .map_err(|_| "Движок голоса не установлен. Запусти установщик с флагом --with-tts (Windows: -WithTts).".to_string())
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).map_err(|e| format!("tts.json повреждён: {e}")))?;
    let python = cfg["python"].as_str().ok_or("в tts.json нет python")?.to_string();
    let dir = cfg["dir"].as_str().ok_or("в tts.json нет dir")?.to_string();
    let port = cfg["port"].as_u64().unwrap_or(8420) as u16;
    let token = make_token();

    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("tts.log"))
        .map_err(|e| e.to_string())?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(python);
    cmd.args(["-m", "w420_tts", "--port", &port.to_string()])
        .current_dir(dir)
        .env("W420_TTS_TOKEN", &token)
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log2));
    if accept_license {
        cmd.env("COQUI_TOS_AGREED", "1");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // no console window
    }
    let child = cmd.spawn().map_err(|e| format!("не удалось запустить движок: {e}"))?;
    *guard = Some((child, token.clone(), port));
    Ok(TtsInfo { port, token })
}

#[tauri::command]
fn tts_stop(state: tauri::State<TtsProc>) {
    if let Ok(mut g) = state.0.lock() {
        if let Some((mut c, _, _)) = g.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Handle to the tray line that shows what the AI agents are doing.
#[cfg(desktop)]
struct Tray {
    agent: tauri::menu::MenuItem<tauri::Wry>,
    pending: tauri::menu::MenuItem<tauri::Wry>,
    autostart: tauri::menu::CheckMenuItem<tauri::Wry>,
}

#[derive(Serialize)]
struct Metrics {
    cpu: f32,
    cores: usize,
    mem_used: u64,
    mem_total: u64,
    uptime: u64,
    os: String,
    host: String,
}

/// Real native metrics for the Holo-HUD.
#[tauri::command]
fn system_metrics(state: tauri::State<Sys>) -> Metrics {
    let mut s = state.0.lock().unwrap();
    s.refresh_cpu();
    s.refresh_memory();
    Metrics {
        cpu: s.global_cpu_info().cpu_usage(),
        cores: s.cpus().len(),
        mem_used: s.used_memory(),
        mem_total: s.total_memory(),
        uptime: System::uptime(),
        os: System::long_os_version().unwrap_or_default(),
        host: System::host_name().unwrap_or_default(),
    }
}

/// The page reports agent state here; it is shown in the tray menu.
#[tauri::command]
fn set_agent_status(app: tauri::AppHandle, text: String) {
    #[cfg(desktop)]
    if let Some(t) = app.try_state::<Tray>() {
        let _ = t.agent.set_text(text);
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, text);
    }
}

/// Tray icon + tooltip + menu line reflect how many AI proposals wait for approval.
#[tauri::command]
fn set_tray_alert(app: tauri::AppHandle, count: u32) {
    #[cfg(desktop)]
    {
        if let Some(tray) = app.tray_by_id("main") {
            let bytes: &[u8] = if count > 0 {
                include_bytes!("../icons/tray-alert.png")
            } else {
                include_bytes!("../icons/tray.png")
            };
            if let Ok(img) = tauri::image::Image::from_bytes(bytes) {
                let _ = tray.set_icon(Some(img));
            }
            let tip = if count > 0 {
                format!("WINDOWS 420 · ждёт подтверждения: {count}")
            } else {
                "WINDOWS 420".to_string()
            };
            let _ = tray.set_tooltip(Some(tip));
        }
        if let Some(t) = app.try_state::<Tray>() {
            let _ = t.pending.set_text(format!("Ожидает подтверждения: {count}"));
        }
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, count);
    }
}

/// Native desktop notification (used when the window is hidden in the tray).
#[tauri::command]
fn notify(app: tauri::AppHandle, title: String, body: String) {
    #[cfg(desktop)]
    {
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().builder().title(title).body(body).show();
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, title, body);
    }
}

#[cfg(desktop)]
fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg(desktop)]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::{
        image::Image,
        menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        Emitter,
    };
    use tauri_plugin_autostart::ManagerExt;

    let status = MenuItem::with_id(app, "status", "● W420 · запуск…", false, None::<&str>)?;
    let agent = MenuItem::with_id(app, "agent", "ИИ: простаивает", false, None::<&str>)?;
    let pending = MenuItem::with_id(app, "pending", "Ожидает подтверждения: 0", false, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "Запускать при входе в систему",
        true,
        app.autolaunch().is_enabled().unwrap_or(false),
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", "Открыть W420", true, None::<&str>)?;
    let term = MenuItem::with_id(app, "nav:term", "Терминал", true, None::<&str>)?;
    let ai = MenuItem::with_id(app, "nav:ai", "AGI-ассистент", true, None::<&str>)?;
    let audit = MenuItem::with_id(app, "nav:audit", "Журнал аудита", true, None::<&str>)?;
    let vault = MenuItem::with_id(app, "nav:vault", "QFS Vault", true, None::<&str>)?;
    let brief = MenuItem::with_id(app, "brief", "Брифинг системы (ИИ)", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Остановить ИИ-задачу", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Заблокировать ключи", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(
        app,
        &[
            &status, &agent, &pending, &sep1, &show, &term, &ai, &audit, &vault, &sep2, &brief,
            &stop, &lock, &sep3, &autostart, &quit,
        ],
    )?;

    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .tooltip("WINDOWS 420")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            "brief" => {
                show_main(app);
                let _ = app.emit("w420:brief", ());
            }
            "stop" => {
                let _ = app.emit("w420:stop-task", ());
            }
            "lock" => {
                let _ = app.emit("w420:lock", ());
            }
            "autostart" => {
                let al = app.autolaunch();
                let now = !al.is_enabled().unwrap_or(false);
                let _ = if now { al.enable() } else { al.disable() };
                if let Some(t) = app.try_state::<Tray>() {
                    let _ = t.autostart.set_checked(al.is_enabled().unwrap_or(now));
                }
            }
            other if other.starts_with("nav:") => {
                show_main(app);
                let _ = app.emit("w420:navigate", other[4..].to_string());
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    // live CPU/RAM line in the menu
    let line = status.clone();
    std::thread::spawn(move || {
        let mut sys = System::new();
        loop {
            sys.refresh_cpu();
            sys.refresh_memory();
            let gb = 1_073_741_824.0_f64;
            let txt = format!(
                "● CPU {:.0}% · RAM {:.1}/{:.1} ГБ",
                sys.global_cpu_info().cpu_usage(),
                sys.used_memory() as f64 / gb,
                sys.total_memory() as f64 / gb
            );
            let _ = line.set_text(txt);
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    });

    app.manage(Tray { agent, pending, autostart });
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default();

    // HTTP from the Rust side (no browser CORS); allowed hosts are limited in capabilities/default.json
    builder = builder.plugin(tauri_plugin_http::init());

    // one instance only: a second launch just brings the window back
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                show_main(app);
            }))
            .plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                Some(vec!["--hidden"]),
            ))
            .plugin(tauri_plugin_notification::init());
    }

    builder
        .manage(Sys(Mutex::new(System::new_all())))
        .manage(TtsProc(Mutex::new(None)))
        .manage(bridge::Bridge::default())
        .manage(tor::Tor::default())
        .manage(sysops::SysOps::default())
        .manage(hosts::HostsManager::default())
        .manage(threats::ThreatMonitor::default())
        .manage(net_scan::NetScanManager::new().expect("не удалось инициализировать NetScanManager"))
        .manage(traffic::TrafficManager::new().expect("не удалось инициализировать TrafficManager"))
        .manage(emergency::EmergencyManager::new())
        .manage(firewall::FirewallManager::new())
        .manage(madre::MadreManager::new())
        .manage(siem::SiemManager::new())
        .manage(edr::EdrManager::new())
        .manage(patch_mgmt::PatchManager::new())
        .manage(vpn::VpnManager::new())
        .manage(web_scan::WebScanManager::new())
        .manage(pki::PkiManager::new())
        .manage(ai_soc::SocManager::new())
        .manage(security_ai::SecurityAIEngine::default())
        .manage(rdesk::RdeskManager::default())
        .manage(sessrec::RecManager::default())
        .manage(reg::RegLocal::open().expect("registry db"))
        .manage(evtlog::EvtLog::open().expect("events db"))
        .invoke_handler(tauri::generate_handler![system_metrics, set_agent_status, set_tray_alert, notify, tts_start, tts_stop, bridge::bridge_start, bridge::bridge_stop, bridge::bridge_status, bridge::config_parse_link, bridge::config_parse_profiles, bridge::config_parse_wireguard, bridge::config_parse_ovpn, bridge::config_build, tor::tor_start, tor::tor_stop, tor::tor_status, sysops::sysops_set_scope, sysops::sysops_get_scope, sysops::sysops_scan_trivy, sysops::sysops_scan_gitleaks, sysops::sysops_fim_baseline, sysops::sysops_fim_check, updates::updates_check, harden::harden_sysctl_plan, harden::harden_sysctl_apply, harden::harden_sysctl_revert, harden::harden_ssh_plan, harden::harden_ssh_apply, harden::harden_ssh_revert, hosts::hosts_add, hosts::hosts_list, hosts::hosts_remove, hosts::hosts_get, hosts::hosts_status, hosts::hosts_status_all, hosts::hosts_exec, hosts::hosts_connect, hosts::hosts_disconnect, threats::threats_scan, threats::threats_last_scan, threats::threats_list, threats::threats_alerts, threats::threats_acknowledge_alert, threats::threats_sync, threats::threats_sources, net_scan::net_scan_subnet, net_scan::net_scan_last, net_scan::net_scan_history, net_scan::net_parse_cidr, net_scan::net_default_ports, net_scan::net_scan_diff, traffic::traffic_start_ids, traffic::traffic_stop, traffic::traffic_status, traffic::traffic_alerts, traffic::traffic_stats, traffic::traffic_capture, traffic::traffic_block_ip, traffic::traffic_unblock_ip, traffic::traffic_blocked_list, traffic::traffic_eve_sync, traffic::traffic_ai_analyze, settings::settings_get, settings::settings_set, ai_providers::ai_providers_list, ai_providers::ai_providers_status, ai_providers::ai_chat, ai_providers::ai_providers_test, ai_providers::ai_providers_test_all, ai_providers::ai_provider_add, ai_providers::ai_provider_add_key, ai_providers::ai_provider_remove, ai_providers::ai_key_remove, ai_providers::ai_key_set_active, ai_providers::ai_provider_set_enabled, ai_providers::ai_provider_set_default, ai_providers::ai_provider_test, ai_providers::ai_provider_list_models, ai_providers::ai_provider_set_models, ai_providers::ai_provider_test_models, ai_providers::ai_provider_model_stats, emergency::emergency_status, emergency::emergency_set, emergency::emergency_rules_preview, emergency::emergency_apply_saved, voice::voice_status, voice::voice_say, voice::voice_hear_b64, voice::voice_command, firewall::fw_profile_apply, firewall::fw_status, firewall::fw_rules_list, firewall::fw_rule_add, firewall::fw_rule_remove, firewall::fw_isolate_host, firewall::fw_logs, siem::siem_ingest, siem::siem_correlate, siem::siem_events, siem::siem_search, siem::siem_dashboard, siem::siem_ai_summary, siem::siem_rules_list, siem::siem_rule_add, siem::siem_rule_remove, siem::siem_rule_toggle, siem::siem_incidents_list, siem::siem_incident_create, siem::siem_incident_set_status, edr::edr_scan_processes, edr::edr_connections, edr::edr_baseline_set, edr::edr_diff, edr::edr_events, edr::edr_watch_start, edr::edr_watch_stop, edr::edr_watch_status, edr::edr_kill_pid, edr::edr_respond, edr::edr_agents_list, patch_mgmt::patch_scan_local, patch_mgmt::patch_scan_all, patch_mgmt::patch_list_updates, patch_mgmt::patch_deploy, patch_mgmt::patch_rollback_plan, patch_mgmt::patch_status, patch_mgmt::patch_ai_assess, vpn::vpn_server_init, vpn::vpn_peer_add, vpn::vpn_peer_revoke, vpn::vpn_peer_list, vpn::vpn_server_start, vpn::vpn_server_stop, vpn::vpn_status, vpn::vpn_traffic, web_scan::web_scan_net, web_scan::web_scan_targets, web_scan::web_vulns_list, web_scan::web_scan_results, web_scan::web_ack_host, web_scan::web_ai_report, web_scan::web_scan_status, web_scan::web_scan_report, pki::pki_ca_init, pki::pki_issue, pki::pki_revoke, pki::pki_verify, pki::pki_crl, pki::pki_list, pki::pki_status, pki::pki_cert_renew, ai_soc::soc_status, ai_soc::soc_autonomous_cycle, ai_soc::soc_incidents, ai_soc::soc_playbook_run, ai_soc::soc_feedback, ai_soc::soc_ai_cycle_report, ai_soc::soc_chat, ai_soc::soc_forecast, agi::agi_status, agi::agi_chat, agi::agi_tools_list, agi::agi_tool_exec, agi::task_start, agi::task_stop, agi::task_status, agi::task_approve, wallet::wallet_create, wallet::wallet_import, wallet::wallet_list, wallet::wallet_reveal, wallet::wallet_remove, wallet::wallet_sign_tx, wallet::wallet_balance, wallet::wallet_send, wallet::wallet_status, pqc::vault_pqc_keygen, pqc::vault_pqc_seal, pqc::vault_pqc_open, pqc::vault_pqc_status, did::did_create, did::did_list, did::did_status, did::did_sign_challenge, did::did_verify, did::did_remove, radio::radio_script, radio::radio_episode, radio::radio_say, radio::radio_status, map::map_generate, map::map_agi_status, rdesk::rdesk_sessions, rdesk::rdesk_connect, rdesk::rdesk_disconnect, rdesk::rdesk_lock_input, rdesk::rdesk_blank_screen, rdesk::rdesk_viewer_join, rdesk::rdesk_screenshot, rdesk::rdesk_set_role, rdesk::rdesk_chat_send, rdesk::rdesk_chat_recv, rdesk::rdesk_xfer_list, rdesk::rdesk_xfer_down, rdesk::rdesk_xfer_up, rat::rat_power, rat::rat_services_list, rat::rat_service_control, rat::rat_log_view, rat::rat_log_clear, rat::rat_disk, rat::rat_pkgs, rat::rat_info_export, rat::rat_wake, argus::argus_procs, argus::argus_metrics_start, argus::argus_metrics_history, argus::argus_ports, argus::argus_file_users, argus::argus_kill, netutil::net_port_check, netutil::net_port_scan, netutil::net_dns_lookup, netutil::net_ping, netutil::net_traceroute, ad::ad_config_set, ad::ad_config_get, ad::ad_ping, ad::ad_tree, ad::ad_users_search, ad::ad_groups, ad::ad_user_unlock, ad::ad_user_reset_password, ad::ad_group_members, ad::ad_group_add_member, ad::ad_group_remove_member, ad::ad_gpo_list, ad::ad_export, sessrec::sessrec_start, sessrec::sessrec_stop, sessrec::sessrec_list, sessrec::sessrec_read_cast, sessrec::sessrec_render_mp4, sessrec::sessrec_verify_chain, smartcard::sc_status, smartcard::sc_slots, smartcard::sc_tokens, smartcard::sc_objects, smartcard::sc_certs, smartcard::sc_sign, reg::reg_local_get, reg::reg_local_set, reg::reg_local_list, reg::reg_local_history, reg::reg_remote_query, reg::reg_remote_set, reg::reg_remote_delete, evtlog::evt_log, evtlog::evt_query, evtlog::evt_stats, evtlog::evt_prune, evtlog::evt_remote_logs, evtlog::evt_remote_query, taskext::taskext_tree, taskext::taskext_kill, taskext::taskext_proc_info, taskext::taskext_autostart_list, taskext::taskext_remote_procs, taskext::taskext_remote_kill, taskext::taskext_remote_tasks, taskext::taskext_remote_autostart, fmgr::fmgr_list, fmgr::fmgr_read, fmgr::fmgr_write, fmgr::fmgr_chmod, fmgr::fmgr_delete, fmgr::fmgr_search, fmgr::fmgr_remote_list, fmgr::fmgr_remote_read, fmgr::fmgr_remote_stat, fmgr::fmgr_remote_search, madre::madre_status, madre::madre_mode_set, madre::madre_allow_add, madre::madre_allow_remove, madre::madre_allow_list, madre::madre_apply, madre::madre_verdict, madre::madre_honeypot_start, madre::madre_honeypot_stop, madre::madre_watchdog_start, madre::madre_watchdog_stop, madre::madre_events, madre::madre_helm, health::hosts_health, health::hosts_health_all])
        .setup(|app| {
            #[cfg(desktop)]
            {
                setup_tray(app)?;
                // started by autostart with --hidden: stay in the tray, otherwise show the window
                if !std::env::args().any(|a| a == "--hidden") {
                    show_main(app.handle());
                }
            }
            #[cfg(not(desktop))]
            {
                let _ = app;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // closing the window hides it to the tray; "Выход" in the tray really quits
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
            #[cfg(not(desktop))]
            {
                let _ = (window, event);
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building W420")
        .run(|app, event| {
            // never leave the TTS engine running after the app quits
            if let tauri::RunEvent::Exit = event {
                if let Some(b) = app.try_state::<bridge::Bridge>() {
                    bridge::kill(&b);
                }
                if let Some(st) = app.try_state::<TtsProc>() {
                    if let Ok(mut g) = st.0.lock() {
                        if let Some((mut c, _, _)) = g.take() {
                            let _ = c.kill();
                        }
                    }
                }
            }
        });
}
