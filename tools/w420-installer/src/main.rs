//! w420-installer — единый установщик на Rust.
//! Создаёт ~/.w420/, качает sidecar-бинарники (sing-box), настраивает TTS,
//! выдаёт CAP_NET_ADMIN для TUN, пишет tts.json.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const APP_NAME: &str = "w420";
const SINGBOX_VERSION: &str = "1.11.8";
const TTS_PORT: u16 = 8420;

struct Args {
    with_tts: bool,
    with_sidecars: bool,
    grant_tun: bool,
    home: PathBuf,
}

fn parse_args() -> Args {
    let mut with_tts = false;
    let mut with_sidecars = true;
    let mut grant_tun = false;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--with-tts" => with_tts = true,
            "--without-sidecars" => with_sidecars = false,
            "--grant-tun" => grant_tun = true,
            _ => {}
        }
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    Args { with_tts, with_sidecars, grant_tun, home }
}

fn w420_dir(home: &Path) -> PathBuf {
    home.join(format!(".{}", APP_NAME))
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("не удалось создать {}: {e}", path.display()))
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    println!("  скачиваю {} → {}", url, dest.display());
    let output = Command::new("curl")
        .args(["-fL", "--progress-bar", "-o", dest.to_str().unwrap(), url])
        .output()
        .map_err(|e| format!("curl не запустился: {e}"))?;
    if !output.status.success() {
        return Err(format!("скачивание {} не удалось: {}", url, String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

fn install_singbox(home: &Path) -> Result<(), String> {
    let w420 = w420_dir(home);
    let sidecar_dir = w420.join("sidecars");
    ensure_dir(&sidecar_dir)?;

    let target = if cfg!(target_os = "linux") {
        if cfg!(target_arch = "x86_64") {
            "sing-box-1.11.8-linux-amd64"
        } else if cfg!(target_arch = "aarch64") {
            "sing-box-1.11.8-linux-arm64"
        } else {
            return Err("неподдерживаемая архитектура для sing-box".into());
        }
    } else if cfg!(target_os = "windows") {
        "sing-box-1.11.8-windows-amd64"
    } else {
        return Err("поддерживаются только Linux и Windows".into());
    };

    let archive = format!("{target}.tar.gz");
    let url = format!("https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/{archive}");
    let archive_path = sidecar_dir.join(&archive);

    download(&url, &archive_path)?;

    // Распаковка
    let status = Command::new("tar")
        .args(["-xzf", archive_path.to_str().unwrap(), "-C", sidecar_dir.to_str().unwrap()])
        .status()
        .map_err(|e| format!("tar не запустился: {e}"))?;

    if !status.success() {
        return Err("распаковка sing-box не удалась".into());
    }

    // Находим бинарник внутри распакованного архива
    let bin_name = if cfg!(target_os = "windows") { "sing-box.exe" } else { "sing-box" };
    let extracted = sidecar_dir.join(format!("{target}/{bin_name}"));
    let final_bin = sidecar_dir.join(bin_name);

    if extracted.exists() {
        fs::rename(&extracted, &final_bin).map_err(|e| format!("перемещение sing-box: {e}"))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&final_bin).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&final_bin, perms).map_err(|e| e.to_string())?;
    }

    // Удаляем архив и распакованную папку
    let _ = fs::remove_file(&archive_path);
    let _ = fs::remove_dir_all(sidecar_dir.join(target));

    println!("  sing-box установлен в {}", final_bin.display());
    Ok(())
}

fn grant_tun_capability(singbox_path: &Path) -> Result<(), String> {
    println!("  выдача CAP_NET_ADMIN для sing-box (TUN)…");

    // setcap на бинарник sing-box
    let setcap = Command::new("setcap")
        .arg("cap_net_admin+ep")
        .arg(singbox_path.to_str().unwrap())
        .output();

    match setcap {
        Ok(output) if output.status.success() => {
            println!("  CAP_NET_ADMIN выдан через setcap");
            return Ok(());
        }
        Ok(_) => {}
        Err(_) => {}
    }

    // Пробуем через sudo
    let sudo = Command::new("sudo")
        .args(["setcap", "cap_net_admin+ep", singbox_path.to_str().unwrap()])
        .output();
    match sudo {
        Ok(output) if output.status.success() => {
            println!("  CAP_NET_ADMIN выдан через sudo setcap");
            Ok(())
        }
        _ => Err(
            format!("не удалось выдать CAP_NET_ADMIN для {}. Запустите вручную: sudo setcap cap_net_admin+ep {}", singbox_path.display(), singbox_path.display())
        ),
    }
}

fn install_tts(home: &Path, with_tts: bool) -> Result<(), String> {
    if !with_tts {
        println!("  TTS пропущен (--with-tts не указан)");
        return Ok(());
    }

    let w420 = w420_dir(home);
    ensure_dir(&w420)?;

    // tts.json — конфиг для tts_start в Tauri
    let tts_json = serde_json::json!({
        "python": "python3",
        "dir": "/opt/w420/tts-server",
        "port": TTS_PORT,
        "engine": "espeak-ng",
        "voice": "ru",
        "speed": 1.0
    });

    let tts_json_path = w420.join("tts.json");
    let mut file = fs::File::create(&tts_json_path).map_err(|e| format!("tts.json: {e}"))?;
    writeln!(file, "{}", serde_json::to_string_pretty(&tts_json).unwrap()).map_err(|e| e.to_string())?;

    // Генерируем токен для TTS (простой, без внешних крейтов)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let token = format!("{now:x}{pid:x}");

    let env_path = w420.join("tts.env");
    let mut env_file = fs::File::create(&env_path).map_err(|e| format!("tts.env: {e}"))?;
    writeln!(env_file, "W420_TTS_TOKEN={token}").map_err(|e| e.to_string())?;

    println!("  tts.json и tts.env созданы в {}", w420.display());
    println!("  Токен TTS: {token}");
    println!("  Запуск TTS: W420_TTS_TOKEN={token} cargo run -p tts-rust");
    Ok(())
}

fn main() {
    let args = parse_args();
    let home = &args.home;
    let w420 = w420_dir(home);

    println!("=== w420-installer ===");
    println!("Домашняя директория: {}", home.display());
    println!("W420 директория: {}", w420.display());

    if let Err(e) = ensure_dir(&w420) {
        eprintln!("Ошибка: {e}");
        std::process::exit(1);
    }

    // 1. Sidecar-бинарники (sing-box)
    let singbox_path = w420.join("sidecars").join(if cfg!(windows) { "sing-box.exe" } else { "sing-box" });
    if args.with_sidecars {
        if let Err(e) = install_singbox(home) {
            eprintln!("Ошибка установки sing-box: {e}");
            std::process::exit(1);
        }
    }

    // 2. TUN capability (не критично — можно сделать вручную позже)
    if args.grant_tun {
        if let Err(e) = grant_tun_capability(&singbox_path) {
            eprintln!("Предупреждение grant-tun: {e}");
            eprintln!("  TUN-интерфейс будет недоступен до ручной настройки.");
        }
    }

    // 3. TTS
    if let Err(e) = install_tts(home, args.with_tts) {
        eprintln!("Ошибка установки TTS: {e}");
        std::process::exit(1);
    }

    println!();
    println!("=== Установка завершена ===");
    println!("Директория: {}", w420.display());
    println!("Sidecars: {}", w420.join("sidecars").display());
    println!("TTS: {}", w420.join("tts.json").display());
    println!();
    println!("Следующие шаги:");
    println!("  1. Запустите приложение: cargo run --bin w420 (в app/src-tauri)");
    println!("  2. Запустите TTS сервер (если нужен):");
    println!("     source ~/.w420/tts.env && cd /home/thomas/w420-install/tts-server/tts-rust && cargo run");
    println!("  3. В UI нажмите 'Запустить мост' для подключения к sing-box");
}
