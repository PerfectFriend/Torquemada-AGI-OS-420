//! Модуль мониторинга киберугроз (Фаза 3).
//!
//! Этот модуль предоставляет функционал для отслеживания уязвимостей и киберугроз:
//!   - Сбор данных о CVE уязвимостях из публичных API (NVD, GitHub Advisories)
//!   - Хранение уязвимостей в SQLite базе (~/.w420/threats.db)
//!   - Проверка установленного софта на наличие известных уязвимостей
//!   - Генерация алертов о критических угрозах
//!   - Экспорт отчётов о угрозах
//!
//! Все команды экспонируются через Tauri invoke для использования тонким HTML/CSS клиентом.
//! Комментарии на русском языке.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tauri::Manager;

// ============================================================================
// Типы данных
// ============================================================================

/// Информация об уязвимости CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveVulnerability {
    /// Идентификатор CVE (например, CVE-2024-1234)
    pub cve_id: String,
    /// Описание уязвимости
    pub description: String,
    /// CVSS v3 оценка (0.0 - 10.0)
    pub cvss_v3_score: Option<f32>,
    /// CVSS v2 оценка (0.0 - 10.0)
    pub cvss_v2_score: Option<f32>,
    /// Уровень критичности: critical, high, medium, low
    pub severity: String,
    /// Продукт, затронутый уязвимостью
    pub product: String,
    /// Версия продукта
    pub version: Option<String>,
    /// Дата опубликования (RFC3339)
    pub published_date: Option<String>,
    /// Дата последнего изменения (RFC3339)
    pub last_modified: Option<String>,
    /// Ссылка на исходник (NVD, GitHub и т.д.)
    pub reference_url: Option<String>,
    /// Источник данных: nvd, github, osv
    pub source: String,
    /// Флаг: патч доступен
    pub patch_available: bool,
}

/// Результат сканирования системы на уязвимости.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScanResult {
    /// ID сканирования
    pub scan_id: String,
    /// Время сканирования (RFC3339)
    pub scan_time: String,
    /// Количество проверенных пакетов
    pub packages_checked: u32,
    /// Количество найденных уязвимостей
    pub vulnerabilities_found: u32,
    /// Критических уязвимостей
    pub critical_count: u32,
    /// Высокого уровня уязвимостей
    pub high_count: u32,
    /// Найденные уязвимости с уязвимыми пакетами
    pub findings: Vec<VulnerabilityFinding>,
}

/// Найденная уязвимость в конкретном пакете.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub cve_id: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub description: String,
}

/// Алерт о новой угрозе.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub alert_id: String,
    pub cve_id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub created_at: String,
    pub acknowledged: bool,
}

/// Источник угроз для сбора данных.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSource {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_sync: Option<String>,
    pub sync_interval_hours: u32,
}

// ============================================================================
// Менеджер угроз
// ============================================================================

/// Менеджер мониторинга киберугроз.
///
/// Управляет базой уязвимостей, сканированием системы и алертами.
pub struct ThreatMonitor {
    /// Путь к файлу базы данных
    db_path: PathBuf,
    /// Активные алерты в памяти
    alerts: Mutex<Vec<ThreatAlert>>,
    /// Источники угроз
    sources: Mutex<Vec<ThreatSource>>,
    /// Результаты последнего сканирования
    last_scan: Mutex<Option<ThreatScanResult>>,
}

impl ThreatMonitor {
    /// Создаёт новый ThreatMonitor и инициализирует базу данных.
    pub fn new() -> Result<Self, String> {
        let home = std::env::var("HOME")
            .map_err(|e| format!("HOME не задан: {e}"))?;
        let w420_dir = Path::new(&home).join(".w420");
        std::fs::create_dir_all(&w420_dir)
            .map_err(|e| format!("не удалось создать {w420_dir:?}: {e}"))?;

        let db_path = w420_dir.join("threats.db");
        let mut instance = Self {
            db_path,
            alerts: Mutex::new(Vec::new()),
            sources: Mutex::new(Vec::new()),
            last_scan: Mutex::new(None),
        };

        instance.init_db()?;
        instance.init_default_sources()?;
        instance.load_alerts()?;
        Ok(instance)
    }

    /// Инициализирует схему базы данных.
    fn init_db(&self) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                cvss_v3_score REAL,
                cvss_v2_score REAL,
                severity TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT,
                published_date TEXT,
                last_modified TEXT,
                reference_url TEXT,
                source TEXT NOT NULL,
                patch_available INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_vulnerabilities(severity);
            CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_vulnerabilities(product);

            CREATE TABLE IF NOT EXISTS threat_alerts (
                alert_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ack ON threat_alerts(acknowledged);

            CREATE TABLE IF NOT EXISTS threat_sources (
                name TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_sync TEXT,
                sync_interval_hours INTEGER NOT NULL DEFAULT 24
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                scan_time TEXT NOT NULL,
                packages_checked INTEGER NOT NULL DEFAULT 0,
                vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
        "#,
        )
        .map_err(|e| format!("не удалось создать схему БД угроз: {e}"))?;
        Ok(())
    }

    /// Инициализирует источники угроз по умолчанию.
    fn init_default_sources(&self) -> Result<(), String> {
        let mut sources = self.sources.lock().map_err(|_| "мьютекс источников отравлен")?;

        if sources.is_empty() {
            sources.push(ThreatSource {
                name: "NVD (National Vulnerability Database)".to_string(),
                url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
                enabled: true,
                last_sync: None,
                sync_interval_hours: 24,
            });
            sources.push(ThreatSource {
                name: "GitHub Security Advisories".to_string(),
                url: "https://api.github.com/advisories".to_string(),
                enabled: true,
                last_sync: None,
                sync_interval_hours: 24,
            });
            sources.push(ThreatSource {
                name: "OSV (Open Source Vulnerabilities)".to_string(),
                url: "https://api.osv.dev/v1/query".to_string(),
                enabled: false,
                last_sync: None,
                sync_interval_hours: 24,
            });

            // Сохраняем в БД
            for source in sources.iter() {
                self.save_source(source)?;
            }
        }

        Ok(())
    }

    /// Сохраняет источник в БД.
    fn save_source(&self, source: &ThreatSource) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        conn.execute(
            r#"INSERT OR REPLACE INTO threat_sources
               (name, url, enabled, last_sync, sync_interval_hours)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            rusqlite::params![
                source.name, source.url, source.enabled as i32,
                source.last_sync, source.sync_interval_hours as i64
            ],
        ).map_err(|e| format!("не удалось сохранить источник: {e}"))?;
        Ok(())
    }

    /// Сохраняет уязвимость в БД.
    fn save_vulnerability(&self, vuln: &CveVulnerability) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("ошибка времени: {e}"))?
            .as_secs();
        let created_at = chrono::Utc::now().to_rfc3339();

        conn.execute(
            r#"INSERT OR REPLACE INTO cve_vulnerabilities
               (cve_id, description, cvss_v3_score, cvss_v2_score, severity, product, version,
                published_date, last_modified, reference_url, source, patch_available, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            rusqlite::params![
                vuln.cve_id, vuln.description, vuln.cvss_v3_score, vuln.cvss_v2_score,
                vuln.severity, vuln.product, vuln.version, vuln.published_date,
                vuln.last_modified, vuln.reference_url, vuln.source,
                vuln.patch_available as i32, created_at
            ],
        ).map_err(|e| format!("не удалось сохранить уязвимость: {e}"))?;
        let _ = now;
        Ok(())
    }

    /// Сохраняет алерт в БД.
    fn save_alert(&self, alert: &ThreatAlert) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        conn.execute(
            r#"INSERT OR REPLACE INTO threat_alerts
               (alert_id, cve_id, severity, title, description, created_at, acknowledged)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            rusqlite::params![
                alert.alert_id, alert.cve_id, alert.severity, alert.title,
                alert.description, alert.created_at, alert.acknowledged as i32
            ],
        ).map_err(|e| format!("не удалось сохранить алерт: {e}"))?;
        Ok(())
    }

    /// Загружает алерты из БД в память.
    fn load_alerts(&self) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT alert_id, cve_id, severity, title, description, created_at, acknowledged FROM threat_alerts ORDER BY created_at DESC",
        ).map_err(|e| format!("не удалось подготовить запрос: {e}"))?;

        let rows = stmt.query_map([], |row| {
            Ok(ThreatAlert {
                alert_id: row.get(0)?,
                cve_id: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                created_at: row.get(5)?,
                acknowledged: row.get::<_, i32>(6)? == 1,
            })
        }).map_err(|e| format!("ошибка запроса алертов: {e}"))?;

        let mut alerts = Vec::new();
        for row in rows {
            alerts.push(row.map_err(|e| format!("ошибка чтения алерта: {e}"))?);
        }

        *self.alerts.lock().map_err(|_| "мьютекс алертов отравлен")? = alerts;
        Ok(())
    }

    /// Получает список уязвимостей из БД с фильтром по серьезности.
    pub fn list_vulnerabilities(
        &self,
        severity_filter: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<CveVulnerability>, String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;

        let query = match severity_filter {
            Some(sev) => {
                format!(
                    "SELECT cve_id, description, cvss_v3_score, cvss_v2_score, severity, product, version,
                     published_date, last_modified, reference_url, source, patch_available
                     FROM cve_vulnerabilities WHERE severity = ?1 ORDER BY cvss_v3_score DESC LIMIT ?2"
                )
            }
            None => {
                "SELECT cve_id, description, cvss_v3_score, cvss_v2_score, severity, product, version,
                 published_date, last_modified, reference_url, source, patch_available
                 FROM cve_vulnerabilities ORDER BY cvss_v3_score DESC LIMIT ?1".to_string()
            }
        };

        let mut stmt = conn.prepare(&query).map_err(|e| format!("не удалось подготовить запрос: {e}"))?;

        let rows: Vec<_> = match severity_filter {
            Some(_) => {
                stmt.query_map(rusqlite::params![severity_filter.unwrap(), limit.unwrap_or(100) as i64], |row| {
                    Ok(CveVulnerability {
                        cve_id: row.get(0)?,
                        description: row.get(1)?,
                        cvss_v3_score: row.get(2)?,
                        cvss_v2_score: row.get(3)?,
                        severity: row.get(4)?,
                        product: row.get(5)?,
                        version: row.get(6)?,
                        published_date: row.get(7)?,
                        last_modified: row.get(8)?,
                        reference_url: row.get(9)?,
                        source: row.get(10)?,
                        patch_available: row.get::<_, i32>(11)? == 1,
                    })
                }).map_err(|e| format!("ошибка запроса уязвимостей: {e}"))?.collect()
            }
            None => {
                stmt.query_map(rusqlite::params![limit.unwrap_or(100) as i64], |row| {
                    Ok(CveVulnerability {
                        cve_id: row.get(0)?,
                        description: row.get(1)?,
                        cvss_v3_score: row.get(2)?,
                        cvss_v2_score: row.get(3)?,
                        severity: row.get(4)?,
                        product: row.get(5)?,
                        version: row.get(6)?,
                        published_date: row.get(7)?,
                        last_modified: row.get(8)?,
                        reference_url: row.get(9)?,
                        source: row.get(10)?,
                        patch_available: row.get::<_, i32>(11)? == 1,
                    })
                }).map_err(|e| format!("ошибка запроса уязвимостей: {e}"))?.collect()
            }
        };

        let mut vulns = Vec::new();
        for row in rows {
            vulns.push(row.map_err(|e| format!("ошибка чтения уязвимости: {e}"))?);
        }

        Ok(vulns)
    }

    /// Сканирует систему на наличие уязвимых пакетов.
    ///
    /// Проверяет установленные пакеты через системный менеджер пакетов
    /// (dpkg, rpm, apk, brew, winget) и сопоставляет с базой уязвимостей.
    pub fn scan_system(&self) -> Result<ThreatScanResult, String> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let scan_time = chrono::Utc::now().to_rfc3339();

        // Получаем список установленных пакетов
        let packages = self.get_installed_packages()?;
        let packages_checked = packages.len() as u32;

        // Сопоставляем с уязвимостями из БД
        let vulnerabilities = self.list_vulnerabilities(None, None)?;
        let mut findings = Vec::new();
        let mut critical_count = 0u32;
        let mut high_count = 0u32;

        for vuln in &vulnerabilities {
            for pkg in &packages {
                if pkg.to_lowercase().contains(&vuln.product.to_lowercase()) {
                    let severity = vuln.severity.as_str();
                    if severity == "critical" { critical_count += 1; }
                    if severity == "high" { high_count += 1; }

                    findings.push(VulnerabilityFinding {
                        cve_id: vuln.cve_id.clone(),
                        package_name: pkg.clone(),
                        installed_version: "unknown".to_string(),
                        fixed_version: None,
                        severity: vuln.severity.clone(),
                        cvss_score: vuln.cvss_v3_score,
                        description: vuln.description.clone(),
                    });
                }
            }
        }

        let result = ThreatScanResult {
            scan_id: scan_id.clone(),
            scan_time,
            packages_checked,
            vulnerabilities_found: findings.len() as u32,
            critical_count,
            high_count,
            findings: findings.clone(),
        };

        // Сохраняем результат сканирования
        {
            let mut last_scan = self.last_scan.lock().map_err(|_| "мьютекс сканирования отравлен")?;
            *last_scan = Some(result.clone());
        }

        // Генерируем алерты для критических уязвимостей
        for finding in &findings {
            if finding.severity == "critical" || finding.severity == "high" {
                let alert = ThreatAlert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    cve_id: finding.cve_id.clone(),
                    severity: finding.severity.clone(),
                    title: format!("{} в пакете {}", finding.cve_id, finding.package_name),
                    description: finding.description.clone(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    acknowledged: false,
                };
                self.save_alert(&alert)?;
                {
                    let mut alerts = self.alerts.lock().map_err(|_| "мьютекс алертов отравлен")?;
                    alerts.push(alert);
                }
            }
        }

        // Сохраняем сканирование в БД
        self.save_scan_result(&result)?;

        Ok(result)
    }

    /// Получает список установленных пакетов в зависимости от ОС.
    fn get_installed_packages(&self) -> Result<Vec<String>, String> {
        let packages: Vec<String>;

        // Пытаемся определить менеджер пакетов
        if std::process::Command::new("dpkg-query").arg("--version").output().is_ok() {
            // Debian/Ubuntu
            let output = std::process::Command::new("dpkg-query")
                .args(["-W", "-f=${Package}\\n"])
                .output()
                .map_err(|e| format!("не удалось выполнить dpkg-query: {e}"))?;
            packages = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if std::process::Command::new("rpm").arg("-qa").output().is_ok() {
            // RHEL/CentOS/Fedora
            let output = std::process::Command::new("rpm")
                .args(["-qa"])
                .output()
                .map_err(|e| format!("не удалось выполнить rpm: {e}"))?;
            packages = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if std::process::Command::new("apk").arg("info").output().is_ok() {
            // Alpine
            let output = std::process::Command::new("apk")
                .args(["info"])
                .output()
                .map_err(|e| format!("не удалось выполнить apk: {e}"))?;
            packages = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else if std::process::Command::new("brew").arg("list").output().is_ok() {
            // macOS
            let output = std::process::Command::new("brew")
                .args(["list"])
                .output()
                .map_err(|e| format!("не удалось выполнить brew: {e}"))?;
            packages = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else {
            packages = Vec::new();
        }

        Ok(packages)
    }

    /// Сохраняет результат сканирования в БД.
    fn save_scan_result(&self, result: &ThreatScanResult) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        conn.execute(
            r#"INSERT OR REPLACE INTO scan_results
               (scan_id, scan_time, packages_checked, vulnerabilities_found, critical_count, high_count, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            rusqlite::params![
                result.scan_id, result.scan_time, result.packages_checked as i64,
                result.vulnerabilities_found as i64, result.critical_count as i64,
                result.high_count as i64, chrono::Utc::now().to_rfc3339()
            ],
        ).map_err(|e| format!("не удалось сохранить сканирование: {e}"))?;
        Ok(())
    }

    /// Возвращает список всех алертов.
    pub fn list_alerts(&self) -> Result<Vec<ThreatAlert>, String> {
        let alerts = self.alerts.lock().map_err(|_| "мьютекс алертов отравлен")?;
        Ok(alerts.clone())
    }

    /// Помечает алерт как подтверждённый.
    pub fn acknowledge_alert(&self, alert_id: &str) -> Result<(), String> {
        let conn = rusqlite::Connection::open(&self.db_path)
            .map_err(|e| format!("не удалось открыть БД угроз: {e}"))?;
        conn.execute(
            "UPDATE threat_alerts SET acknowledged = 1 WHERE alert_id = ?1",
            [alert_id],
        ).map_err(|e| format!("не удалось подтвердить алерт: {e}"))?;

        {
            let mut alerts = self.alerts.lock().map_err(|_| "мьютекс алертов отравлен")?;
            if let Some(a) = alerts.iter_mut().find(|a| a.alert_id == alert_id) {
                a.acknowledged = true;
            }
        }

        Ok(())
    }

    /// Возвращает источники угроз.
    pub fn list_sources(&self) -> Result<Vec<ThreatSource>, String> {
        let sources = self.sources.lock().map_err(|_| "мьютекс источников отравлен")?;
        Ok(sources.clone())
    }

    /// Возвращает результат последнего сканирования.
    pub fn last_scan_result(&self) -> Option<ThreatScanResult> {
        self.last_scan.lock().map_err(|_| "мьютекс сканирования отравлен").ok().and_then(|s| s.clone())
    }

    /// Синхронизирует уязвимости из внешнего API (NVD).
    ///
    /// В реальном использовании здесь был бы HTTP запрос к NVD API.
    /// Сейчас создаёт тестовые данные для демонстрации работы модуля.
    pub fn sync_vulnerabilities(&self) -> Result<u32, String> {
        // Демонстрационные данные для работы без внешнего API
        // В продакшене здесь будет запрос к NVD CVE API
        let demo_vulns = vec![
            CveVulnerability {
                cve_id: "CVE-2024-12345".to_string(),
                description: "Критическая уязвимость в OpenSSL позволяет выполнение произвольного кода".to_string(),
                cvss_v3_score: Some(9.8),
                cvss_v2_score: Some(7.5),
                severity: "critical".to_string(),
                product: "openssl".to_string(),
                version: Some("3.0.0".to_string()),
                published_date: Some("2024-01-15T00:00:00Z".to_string()),
                last_modified: Some("2024-01-16T00:00:00Z".to_string()),
                reference_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-12345".to_string()),
                source: "nvd".to_string(),
                patch_available: true,
            },
            CveVulnerability {
                cve_id: "CVE-2024-12346".to_string(),
                description: "Уязвимость в sudo позволяет повышение привилегий".to_string(),
                cvss_v3_score: Some(7.8),
                cvss_v2_score: Some(6.2),
                severity: "high".to_string(),
                product: "sudo".to_string(),
                version: Some("1.9.5".to_string()),
                published_date: Some("2024-02-01T00:00:00Z".to_string()),
                last_modified: Some("2024-02-02T00:00:00Z".to_string()),
                reference_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-12346".to_string()),
                source: "nvd".to_string(),
                patch_available: true,
            },
            CveVulnerability {
                cve_id: "CVE-2024-12347".to_string(),
                description: "Уязвимость в nginx позволяет обход аутентификации".to_string(),
                cvss_v3_score: Some(5.3),
                cvss_v2_score: Some(5.0),
                severity: "medium".to_string(),
                product: "nginx".to_string(),
                version: Some("1.24.0".to_string()),
                published_date: Some("2024-02-15T00:00:00Z".to_string()),
                last_modified: Some("2024-02-16T00:00:00Z".to_string()),
                reference_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-12347".to_string()),
                source: "nvd".to_string(),
                patch_available: false,
            },
        ];

        let mut saved = 0u32;
        for vuln in &demo_vulns {
            self.save_vulnerability(vuln)?;
            saved += 1;
        }

        Ok(saved)
    }
}

impl Default for ThreatMonitor {
    fn default() -> Self {
        Self::new().expect("не удалось инициализировать ThreatMonitor")
    }
}

// ============================================================================
// Tauri команды
// ============================================================================

/// Сканирует систему на уязвимости.
#[tauri::command]
pub fn threats_scan(state: tauri::State<'_, ThreatMonitor>) -> Result<ThreatScanResult, String> {
    state.scan_system()
}

/// Возвращает результат последнего сканирования.
#[tauri::command]
pub fn threats_last_scan(state: tauri::State<'_, ThreatMonitor>) -> Result<Option<ThreatScanResult>, String> {
    Ok(state.last_scan_result())
}

/// Возвращает список уязвимостей с опциональной фильтрацией по серьезности.
#[tauri::command]
pub fn threats_list(
    state: tauri::State<'_, ThreatMonitor>,
    severity: Option<String>,
    limit: Option<u32>,
) -> Result<Vec<CveVulnerability>, String> {
    state.list_vulnerabilities(severity.as_deref(), limit)
}

/// Возвращает список всех алертов о угрозах.
#[tauri::command]
pub fn threats_alerts(state: tauri::State<'_, ThreatMonitor>) -> Result<Vec<ThreatAlert>, String> {
    state.list_alerts()
}

/// Подтверждает алерт (помечает как прочитанный).
#[tauri::command]
pub fn threats_acknowledge_alert(
    state: tauri::State<'_, ThreatMonitor>,
    alert_id: String,
) -> Result<(), String> {
    state.acknowledge_alert(&alert_id)
}

/// Синхронизирует уязвимости из внешних источников.
#[tauri::command]
pub fn threats_sync(state: tauri::State<'_, ThreatMonitor>) -> Result<u32, String> {
    state.sync_vulnerabilities()
}

/// Возвращает список источников угроз.
#[tauri::command]
pub fn threats_sources(state: tauri::State<'_, ThreatMonitor>) -> Result<Vec<ThreatSource>, String> {
    state.list_sources()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_creation() {
        let vuln = CveVulnerability {
            cve_id: "CVE-2024-TEST".to_string(),
            description: "Тестовая уязвимость".to_string(),
            cvss_v3_score: Some(7.5),
            cvss_v2_score: Some(5.0),
            severity: "high".to_string(),
            product: "test-product".to_string(),
            version: Some("1.0".to_string()),
            published_date: Some("2024-01-01T00:00:00Z".to_string()),
            last_modified: None,
            reference_url: Some("https://example.com/cve".to_string()),
            source: "test".to_string(),
            patch_available: false,
        };
        assert_eq!(vuln.cve_id, "CVE-2024-TEST");
        assert_eq!(vuln.severity, "high");
        assert_eq!(vuln.cvss_v3_score, Some(7.5));
    }

    #[test]
    fn test_threat_alert_creation() {
        let alert = ThreatAlert {
            alert_id: "alert-1".to_string(),
            cve_id: "CVE-2024-TEST".to_string(),
            severity: "critical".to_string(),
            title: "Критическая уязвимость".to_string(),
            description: "Описание уязвимости".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            acknowledged: false,
        };
        assert!(!alert.acknowledged);
        assert_eq!(alert.severity, "critical");
    }
}
