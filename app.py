"""
Android Theft Emergency Response Console.

A desktop emergency runbook built with Tkinter and Fernet authenticated
encryption. Provides minute-by-minute triage checklists, one-click browser
navigation, encrypted local storage for IMEI and 2FA backup codes, USB ADB
device autofill, clipboard utilities, a non-destructive drill mode, and an
append-only ISO-8601 timestamped audit log.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
MIN_PASSWORD_LENGTH = 8


@dataclass
class DeviceProfile:
    """Stores static device identifiers and recovery credentials."""

    device_model: str = "Android Telefon"
    phone_number: str = "+90 5XX XXX XX XX"
    imei_1: str = "000000000000000"
    imei_2: str = "000000000000000"
    operator_hotline: str = "Turkcell: 0532 532 00 00 | Türk Telekom: 444 1 444 | Vodafone: 0542 542 00 00"
    backup_codes: list[str] = field(
        default_factory=lambda: [
            "1234-5678",
            "2345-6789",
            "3456-7890",
            "4567-8901",
        ]
    )


@dataclass
class AdbDeviceInfo:
    """Holds device identifiers retrieved from a USB-connected Android phone."""

    device_model: str
    imei_1: str
    imei_2: str
    phone_number: str


@dataclass
class ChecklistItem:
    """Represents a single time-critical action item in the response plan."""

    item_id: str
    phase: str
    title: str
    details: list[str]
    action_url: str | None = None
    action_label: str | None = None
    completed: bool = False


class AdbDeviceReader:
    """Queries a USB-connected Android device via ADB for model and dual-SIM IMEIs."""

    _IMEI_TRANSACTIONS = ("4", "3", "1")
    _MSISDN_TRANSACTIONS = ("17", "16", "15", "13")

    def __init__(self) -> None:
        self._adb_path = self._resolve_adb_binary()

    @staticmethod
    def _resolve_adb_binary() -> str | None:
        """Finds the ADB executable in PATH or standard platform-tools directories."""
        from_path = shutil.which("adb")
        if from_path:
            return from_path

        if sys.platform == "win32":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            candidates = [
                Path(local_app_data) / "Android" / "Sdk" / "platform-tools" / "adb.exe",
                Path("C:/platform-tools/adb.exe"),
                Path("C:/adb/adb.exe"),
            ]
            for candidate in candidates:
                if candidate.is_file():
                    return str(candidate)

        return None

    def read_connected_device(self) -> AdbDeviceInfo:
        """Connects to the first authorized ADB device and extracts hardware identifiers."""
        if not self._adb_path:
            raise RuntimeError(
                "Bilgisayarda ADB (Android Platform Tools) bulunamadı. "
                "Kurup PATH'e ekleyin veya bilgileri elle girin."
            )

        serial = self._get_authorized_serial()
        model = self._read_device_model(serial)
        imei_1 = self._read_imei_for_slot(serial, 0)
        imei_2 = self._read_imei_for_slot(serial, 1)

        if imei_2 and imei_2 == imei_1:
            imei_2 = ""

        phone_number = self._read_phone_number(serial)

        if not model and not imei_1 and not imei_2:
            raise RuntimeError(
                "Cihaza erişildi ancak üretici güvenlik kısıtlaması nedeniyle model veya IMEI okunamadı."
            )

        return AdbDeviceInfo(
            device_model=model,
            imei_1=imei_1,
            imei_2=imei_2,
            phone_number=phone_number,
        )

    def _run_adb(self, args: list[str], timeout: float = 8.0) -> str:
        """Executes an ADB subcommand without spawning a visible console window."""
        if not self._adb_path:
            raise RuntimeError("ADB binary path is unavailable.")

        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        completed = subprocess.run(
            [self._adb_path, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=creation_flags,
            check=False,
        )
        return f"{completed.stdout}\n{completed.stderr}".strip()

    def _get_authorized_serial(self) -> str:
        """Verifies USB debugging state and returns the active device serial."""
        output = self._run_adb(["devices"])
        devices: list[tuple[str, str]] = []

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("List of devices", "*")):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                devices.append((parts[0], parts[1]))

        if not devices:
            raise RuntimeError(
                "USB ile bağlı Android cihaz bulunamadı. "
                "Kabloyu bağlayın ve Geliştirici Seçenekleri > USB Hata Ayıklama ayarını açın."
            )

        for serial, state in devices:
            if state == "device":
                return serial

        first_state = devices[0][1]
        if first_state == "unauthorized":
            raise RuntimeError(
                "USB hata ayıklama yetkisi verilmemiş. "
                "Telefon ekranındaki 'USB Hata Ayıklamaya İzin Ver' penceresini onaylayın."
            )

        raise RuntimeError(f"Cihaz hazır değil (ADB durumu: {first_state}). USB kablosunu çıkarıp takın.")

    def _read_device_model(self, serial: str) -> str:
        """Reads the human-readable marketing or hardware model name."""
        market_props = (
            "ro.product.vendor.marketname",
            "ro.product.marketname",
            "ro.vendor.oplus.market.name",
            "ro.config.marketing_name",
        )
        for prop in market_props:
            value = self._get_prop(serial, prop)
            if value:
                return value

        manufacturer = self._get_prop(serial, "ro.product.manufacturer")
        model = self._get_prop(serial, "ro.product.model")
        if manufacturer and model:
            if model.lower().startswith(manufacturer.lower()):
                return model
            return f"{manufacturer.capitalize()} {model}"
        return model or manufacturer

    def _get_prop(self, serial: str, prop_name: str) -> str:
        """Fetches a single Android system property via getprop."""
        output = self._run_adb(["-s", serial, "shell", "getprop", prop_name])
        cleaned = output.strip()
        if not cleaned or cleaned.startswith(("error:", "adb:")):
            return ""
        return cleaned

    def _read_imei_for_slot(self, serial: str, slot_index: int) -> str:
        """Queries iphonesubinfo across Android API transaction codes for a SIM slot."""
        for tx_code in self._IMEI_TRANSACTIONS:
            output = self._run_adb(
                [
                    "-s",
                    serial,
                    "shell",
                    "service",
                    "call",
                    "iphonesubinfo",
                    tx_code,
                    "i32",
                    str(slot_index),
                    "s16",
                    "com.android.shell",
                ]
            )
            digits = self._extract_imei_digits(output)
            if digits:
                return digits

        if slot_index == 0:
            legacy_output = self._run_adb(
                ["-s", serial, "shell", "service", "call", "iphonesubinfo", "1"]
            )
            return self._extract_imei_digits(legacy_output)

        return ""

    def _read_phone_number(self, serial: str) -> str:
        """Attempts to read the SIM MSISDN phone number if provisioned by the carrier."""
        for tx_code in self._MSISDN_TRANSACTIONS:
            output = self._run_adb(
                [
                    "-s",
                    serial,
                    "shell",
                    "service",
                    "call",
                    "iphonesubinfo",
                    tx_code,
                    "i32",
                    "0",
                    "s16",
                    "com.android.shell",
                ]
            )
            ascii_preview = self._extract_parcel_ascii(output)
            cleaned = "".join(ch for ch in ascii_preview if ch.isdigit() or ch == "+")
            if len(cleaned) >= 10:
                return cleaned
        return ""

    @classmethod
    def _extract_imei_digits(cls, parcel_output: str) -> str:
        """Extracts a 14-to-16 digit IMEI string from an Android Parcel dump."""
        ascii_preview = cls._extract_parcel_ascii(parcel_output)
        digits = "".join(ch for ch in ascii_preview if ch.isdigit())
        if 14 <= len(digits) <= 16:
            return digits
        return ""

    @staticmethod
    def _extract_parcel_ascii(parcel_output: str) -> str:
        """Joins the single-quoted ASCII preview columns from a service call Parcel dump."""
        if "Parcel(" not in parcel_output or "Exception" in parcel_output:
            return ""
        chunks = re.findall(r"'([^']*)'", parcel_output)
        return "".join(chunks)


class EncryptedVaultRepository:
    """Manages PBKDF2 key derivation and Fernet encryption for the local vault."""

    def __init__(self, vault_path: Path, legacy_json_path: Path | None = None) -> None:
        self._vault_path = vault_path
        self._legacy_json_path = legacy_json_path
        self._derived_key: bytearray | None = None
        self._salt: bytes | None = None
        self._iterations: int = PBKDF2_ITERATIONS

    @property
    def exists(self) -> bool:
        """Returns True if an encrypted vault file exists on disk."""
        return self._vault_path.exists()

    @property
    def is_unlocked(self) -> bool:
        """Returns True when the derived encryption key is active in memory."""
        return self._derived_key is not None

    @property
    def has_legacy_plaintext(self) -> bool:
        """Returns True if an unencrypted JSON profile exists on disk."""
        return self._legacy_json_path is not None and self._legacy_json_path.exists()

    def initialize_vault(self, master_password: str, initial_profile: DeviceProfile) -> None:
        """Creates a new encrypted vault with a fresh random salt."""
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._iterations = PBKDF2_ITERATIONS
        self._set_derived_key(master_password, self._salt, self._iterations)
        self.save(initial_profile)

    def unlock(self, master_password: str) -> DeviceProfile:
        """Derives the vault key from the master password and decrypts the profile."""
        if not self._vault_path.exists():
            raise FileNotFoundError("Şifreli kasa dosyası bulunamadı.")

        envelope = json.loads(self._vault_path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict):
            raise TypeError("Kasa dosyası geçersiz JSON zarfı içeriyor.")
        if not isinstance(envelope.get("ciphertext"), str):
            raise TypeError("Kasa şifre metni geçersiz.")
        if not isinstance(envelope.get("salt"), str):
            raise TypeError("Kasa tuz bilgisi geçersiz.")

        salt = base64.b64decode(envelope["salt"].encode("ascii"), validate=True)
        if len(salt) != SALT_BYTES:
            raise ValueError("Kasa tuz uzunluğu geçersiz.")
        iterations = int(envelope.get("iterations", PBKDF2_ITERATIONS))
        if not 100_000 <= iterations <= 10_000_000:
            raise ValueError("Kasa iterasyon sayısı geçersiz.")
        ciphertext = envelope["ciphertext"].encode("utf-8")

        candidate_key = self._derive_fernet_key(master_password, salt, iterations)
        try:
            fernet = Fernet(bytes(candidate_key))
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            self._wipe_bytearray(candidate_key)
            raise

        self.lock()
        self._salt = salt
        self._iterations = iterations
        self._derived_key = candidate_key

        raw_data = json.loads(plaintext.decode("utf-8"))
        return self._deserialize_profile(raw_data)

    def save(self, profile: DeviceProfile) -> None:
        """Encrypts and persists the device profile using the active vault key."""
        if self._derived_key is None or self._salt is None:
            raise RuntimeError("Kasa kilitli; veriler kaydedilemez.")

        fernet = Fernet(bytes(self._derived_key))
        payload = json.dumps(asdict(profile), ensure_ascii=False).encode("utf-8")
        token = fernet.encrypt(payload).decode("utf-8")

        envelope = {
            "version": 1,
            "kdf": "pbkdf2-hmac-sha256",
            "iterations": self._iterations,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "ciphertext": token,
        }
        temporary_path = self._vault_path.with_name(
            f".{self._vault_path.name}.{secrets.token_hex(6)}.tmp"
        )
        try:
            with temporary_path.open("w", encoding="utf-8") as handle:
                json.dump(envelope, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self._vault_path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
        current_profile: DeviceProfile,
    ) -> None:
        """Verifies the current password and re-encrypts the vault with a new salt."""
        self.unlock(current_password)
        self.initialize_vault(new_password, current_profile)

    def import_and_shred_legacy_plaintext(self) -> DeviceProfile | None:
        """Loads an existing plaintext JSON profile and securely overwrites the file."""
        if not self.has_legacy_plaintext or self._legacy_json_path is None:
            return None

        try:
            raw_data = json.loads(self._legacy_json_path.read_text(encoding="utf-8"))
            profile = self._deserialize_profile(raw_data)
            file_size = self._legacy_json_path.stat().st_size
            with self._legacy_json_path.open("r+b") as handle:
                handle.write(b"\x00" * max(file_size, 64))
                handle.flush()
                os.fsync(handle.fileno())
            self._legacy_json_path.unlink()
            return profile
        except (OSError, json.JSONDecodeError):
            return None

    def lock(self) -> None:
        """Zeroes the derived encryption key in memory and marks the vault locked."""
        if self._derived_key is not None:
            self._wipe_bytearray(self._derived_key)
            self._derived_key = None

    def _set_derived_key(self, password: str, salt: bytes, iterations: int) -> None:
        """Replaces the active derived key in memory."""
        self.lock()
        self._derived_key = self._derive_fernet_key(password, salt, iterations)

    @staticmethod
    def _derive_fernet_key(password: str, salt: bytes, iterations: int) -> bytearray:
        """Derives a URL-safe base64 32-byte Fernet key using PBKDF2-HMAC-SHA256."""
        raw_dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
        return bytearray(base64.urlsafe_b64encode(raw_dk))

    @staticmethod
    def _wipe_bytearray(buffer: bytearray) -> None:
        """Overwrites a mutable byte buffer with zeroes."""
        for index in range(len(buffer)):
            buffer[index] = 0

    @staticmethod
    def _deserialize_profile(raw_data: dict[str, Any]) -> DeviceProfile:
        """Constructs a DeviceProfile instance from a parsed dictionary."""
        if not isinstance(raw_data, dict):
            raise TypeError("Şifreli profil verisi geçersiz.")

        backup_codes = raw_data.get("backup_codes", [])
        if not isinstance(backup_codes, list) or not all(
            isinstance(code, str) for code in backup_codes
        ):
            raise TypeError("Yedek kod listesi geçersiz.")

        return DeviceProfile(
            device_model=raw_data.get("device_model", "Android Telefon"),
            phone_number=raw_data.get("phone_number", ""),
            imei_1=raw_data.get("imei_1", ""),
            imei_2=raw_data.get("imei_2", ""),
            operator_hotline=raw_data.get("operator_hotline", ""),
            backup_codes=raw_data.get("backup_codes", []),
        )


class AuditLogger:
    """Writes ISO-8601 timestamped events to disk or isolates them in drill mode."""

    def __init__(
        self,
        output_dir: Path,
        on_entry: Callable[[str], None] | None = None,
        dry_run: bool = False,
    ) -> None:
        timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_path = output_dir / f"Hirsizlik_Mudahale_Tutanagi_{timestamp_slug}.txt"
        self._on_entry = on_entry
        self._dry_run = dry_run
        self._file_initialized = False
        self._session_started_iso = self._now_iso()
        self._buffered_system_entries: list[str] = []

    @property
    def log_path(self) -> Path:
        """Returns the target file system path of the official audit log."""
        return self._log_path

    @property
    def is_dry_run(self) -> bool:
        """Returns True when drill mode is active and disk writes are suppressed."""
        return self._dry_run

    @property
    def has_official_file(self) -> bool:
        """Returns True if an official report file has been created on disk."""
        return self._file_initialized and self._log_path.exists()

    def set_dry_run(self, enabled: bool) -> None:
        """Toggles drill mode and clears buffered pre-incident system lines when enabled."""
        self._dry_run = enabled
        if enabled and not self._file_initialized:
            self._buffered_system_entries.clear()

    def _ensure_file_initialized(self) -> None:
        """Creates the official incident log file on disk upon the first live action."""
        if self._file_initialized:
            return

        header = (
            "====================================================================\n"
            "ANDROID HIRSIZLIK ACIL MUDAHALE - ZAMAN DAMGALI OLAY KAYDI\n"
            f"Oturum Baslangici: {self._session_started_iso}\n"
            "====================================================================\n\n"
        )
        initial_content = header + "".join(self._buffered_system_entries)
        self._log_path.write_text(initial_content, encoding="utf-8")
        self._buffered_system_entries.clear()
        self._file_initialized = True

    def log(self, category: str, message: str) -> str:
        """Formats a timestamped log line, updates the UI, and persists only in live mode."""
        if self._dry_run:
            entry = f"[{self._now_iso()}] [TATBİKAT] [{category}] {message}\n"
            if self._on_entry is not None:
                self._on_entry(entry)
            return entry

        entry = f"[{self._now_iso()}] [{category}] {message}\n"
        if self._on_entry is not None:
            self._on_entry(entry)

        if category == "SİSTEM" and not self._file_initialized:
            self._buffered_system_entries.append(entry)
            return entry

        self._ensure_file_initialized()
        with self._log_path.open("a", encoding="utf-8") as handle:
            handle.write(entry)
        return entry

    @staticmethod
    def _now_iso() -> str:
        """Returns the current local time in ISO-8601 format with timezone offset."""
        return datetime.now().astimezone().isoformat(timespec="seconds")


class ClipboardManager:
    """Copies critical strings to the system clipboard and records audit logs."""

    def __init__(self, root: tk.Tk, logger: AuditLogger) -> None:
        self._root = root
        self._logger = logger

    def copy_text(self, label: str, value: str, mask_in_log: bool = False) -> bool:
        """Copies a value to the system clipboard and logs the action."""
        cleaned = value.strip()
        if not cleaned:
            messagebox.showwarning("Boş Değer", f"{label} için kayıtlı bir değer bulunamadı.")
            return False

        self._root.clipboard_clear()
        self._root.clipboard_append(cleaned)
        self._root.update()

        logged_value = f"{cleaned[:2]}****{cleaned[-2:]}" if mask_in_log and len(cleaned) > 4 else cleaned
        self._logger.log("PANO", f"{label} ({logged_value}) panoya kopyalandı.")
        return True


def build_default_checklist() -> list[ChecklistItem]:
    """Constructs the minute-by-minute emergency response checklist."""
    return [
        ChecklistItem(
            item_id="ADIM-01",
            phase="0-5. DAKİKA: UZAKTAN KİLİTLEME VE VERİ KORUMA",
            title="Google Uzaktan Kilitleme (Remote Lock) Tetikle",
            details=[
                "Google hesabına tam giriş gerekmeden sadece telefon numarası ve güvenlik yanıtıyla ekranı kilitler.",
                "Hattı dondurmadan ÖNCE uygula; mobil veri kesilirse kilit komutu cihaza ulaşmaz.",
            ],
            action_url="https://www.android.com/lock",
            action_label="android.com/lock Aç",
        ),
        ChecklistItem(
            item_id="ADIM-02",
            phase="0-5. DAKİKA: UZAKTAN KİLİTLEME VE VERİ KORUMA",
            title="Cihazımı Bul Üzerinden Konum Al ve Cihazı Sıfırla",
            details=[
                "2FA çalınan telefona bildirim gönderirse üstteki 8 haneli Google yedek kodlarından biriyle giriş yap.",
                "Son konum ve saat bilgisinin ekran görüntüsünü al (kolluk tutanağı için kanıt).",
                "Banka uygulamaları risk altındaysa 'Cihazı Sıfırla' komutunu ver (FRP kilidi aktif kalır).",
            ],
            action_url="https://www.google.com/android/find",
            action_label="Cihazımı Bul Aç",
        ),
        ChecklistItem(
            item_id="ADIM-03",
            phase="5-15. DAKİKA: OPERATÖR VE BANKA BLOKAJI",
            title="Mobil Operatörü Arayarak Hattı Geçici Olarak Dondur",
            details=[
                "Turkcell: 0532 532 00 00 | Türk Telekom: 444 1 444 | Vodafone: 0542 542 00 00.",
                "Hattı kalıcı iptal ettirme; 'kayıp/çalıntı nedeniyle geçici kullanıma kapatma' talep et.",
                "SMS tabanlı banka şifre sıfırlama ve onay kodu saldırılarını bu adımda kesmiş olursun.",
            ],
        ),
        ChecklistItem(
            item_id="ADIM-04",
            phase="5-15. DAKİKA: OPERATÖR VE BANKA BLOKAJI",
            title="Mobil Şubesi Yüklü Tüm Bankaların Acil Hatlarını Ara",
            details=[
                "Sesli yanıtta 'Kayıp / Çalıntı / Şüpheli İşlem' menüsünden doğrudan müşteri temsilcisine bağlan.",
                "Mobil bankacılık erişimini ve çalınan cihaz eşleşmesini iptal ettir.",
                "NFC / temassız mobil ödemeye tanımlı banka ve kredi kartlarını yenilemeye al.",
            ],
        ),
        ChecklistItem(
            item_id="ADIM-05",
            phase="15-30. DAKİKA: HESAP VE OTURUM İZOLASYONU",
            title="Çalınan Cihazın Google Oturumunu Kapat ve Parolayı Değiştir",
            details=[
                "Aktif cihazlar listesinden çalınan telefonu bulup 'Oturumu Kapat' seçeneğine tıkla.",
                "Google hesap parolanı değiştir ve 2 adımlı doğrulama cihazlarından eski telefonu sil.",
                "Yeni 8 haneli yedek kodlar (Backup Codes) üretip çevrimdışı kaydet.",
            ],
            action_url="https://myaccount.google.com/device-activity",
            action_label="Google Cihazları Aç",
        ),
        ChecklistItem(
            item_id="ADIM-06",
            phase="15-30. DAKİKA: HESAP VE OTURUM İZOLASYONU",
            title="e-Devlet, İkincil E-posta ve Mesajlaşma Oturumlarını Kapat",
            details=[
                "e-Devlet şifreni değiştir ve 'Güvenlik ve Ayarlar' altından aktif mobil oturumu sonlandır.",
                "İkincil e-posta, bulut depolama ve varsa borsa/finans hesaplarında tüm oturumlardan çık.",
            ],
            action_url="https://www.turkiye.gov.tr",
            action_label="e-Devlet Aç",
        ),
        ChecklistItem(
            item_id="ADIM-07",
            phase="30-90. DAKİKA: BTK IMEI KAPATMA VE RESMİ TUTANAK",
            title="BTK İhbar Hattı (120) veya e-Devlet ile IMEI 1 ve IMEI 2'yi Kapat",
            details=[
                "BTK Bilgi ve İhbar Merkezi (120) veya e-Devlet üzerinden kayıp/çalıntı bildirimi yap.",
                "İkinci SIM yuvasının aktif kalmaması için HEM IMEI 1 HEM DE IMEI 2 numarasını bildir.",
                "Verilen BTK ihbar takip numarasını sağ alttaki kutuya yazıp kaydet.",
            ],
            action_url="https://www.turkiye.gov.tr/btk-kayip-calinti-ihbari",
            action_label="BTK İhbar Ekranı",
        ),
        ChecklistItem(
            item_id="ADIM-08",
            phase="30-90. DAKİKA: BTK IMEI KAPATMA VE RESMİ TUTANAK",
            title="Polis veya Jandarma Merkezine Giderek Resmi Tutanak Tuttur",
            details=[
                "Cihaz faturası (veya kutu IMEI etiketi), BTK takip numarası ve konum ekran görüntüsünü sun.",
                "Tutanağın onaylı suretini al (banka harcama ve kredi itirazlarında hukuki milat sayılır).",
            ],
        ),
        ChecklistItem(
            item_id="ADIM-09",
            phase="24 SAAT İÇİNDE: YEDEK SIM VE PAROLA ROTASYONU",
            title="Yedek SIM Kart Çıkar ve Banka SIM Blokelerini Kaldır",
            details=[
                "Operatör bayisinden kimliğinle aynı numaraya ait yeni SIM kart çıkart.",
                "WhatsApp'ı yeni telefonda etkinleştirerek eski cihazdaki oturumu otomatik düşür.",
                "Yedek SIM sonrası bankaların otomatik koyduğu SIM blokesini ATM veya çağrı merkezinden kaldır.",
            ],
        ),
        ChecklistItem(
            item_id="ADIM-10",
            phase="24 SAAT İÇİNDE: YEDEK SIM VE PAROLA ROTASYONU",
            title="Tarayıcıda Kayıtlı Kritik Parolaları Yenile",
            details=[
                "Google Şifre Yöneticisi'nde kayıtlı kritik servis parolalarını sıfırla.",
            ],
            action_url="https://passwords.google.com",
            action_label="Şifre Yöneticisi",
        ),
    ]


class VaultSetupDialog(tk.Toplevel):
    """Modal dialog for creating a new master-password-protected vault."""

    def __init__(
        self,
        parent: tk.Tk,
        vault: EncryptedVaultRepository,
        on_initialized: Callable[[DeviceProfile, bool], None],
    ) -> None:
        super().__init__(parent)
        self.title("Şifreli Cihaz Kasası Kurulumu")
        self.geometry("490x350")
        self.minsize(450, 330)
        self.resizable(True, True)
        self.configure(bg="#181A1F")
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._on_initialized = on_initialized
        self._show_var = tk.BooleanVar(value=False)

        container = tk.Frame(self, bg="#181A1F", padx=18, pady=16)
        container.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            container,
            text="Yerel Kasa İçin Ana Parola Oluştur",
            bg="#181A1F",
            fg="#F8FAFC",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            container,
            text="IMEI numaralarını ve Google 2FA yedek kodlarını AES-128 / PBKDF2 ile şifreler.",
            bg="#181A1F",
            fg="#94A3B8",
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 12))

        tk.Label(
            container,
            text=f"Ana Parola (en az {MIN_PASSWORD_LENGTH} karakter):",
            bg="#181A1F",
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        self._pw_entry = tk.Entry(
            container,
            show="*",
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Segoe UI", 10),
        )
        self._pw_entry.pack(fill=tk.X, ipady=5, pady=(2, 8))
        self._pw_entry.focus_set()

        tk.Label(
            container,
            text="Ana Parola (Tekrar):",
            bg="#181A1F",
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        self._confirm_entry = tk.Entry(
            container,
            show="*",
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Segoe UI", 10),
        )
        self._confirm_entry.pack(fill=tk.X, ipady=5, pady=(2, 6))
        self._confirm_entry.bind("<Return>", lambda _event: self._handle_create())

        tk.Checkbutton(
            container,
            text="Parolayı göster",
            variable=self._show_var,
            command=self._toggle_visibility,
            bg="#181A1F",
            fg="#94A3B8",
            selectcolor="#0F172A",
            activebackground="#181A1F",
            activeforeground="#F8FAFC",
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        self._status_label = tk.Label(
            container,
            text="",
            bg="#181A1F",
            fg="#F87171",
            font=("Segoe UI", 9),
            anchor="w",
        )
        self._status_label.pack(fill=tk.X, pady=(4, 6))

        btn_row = tk.Frame(container, bg="#181A1F")
        btn_row.pack(fill=tk.X, pady=(4, 0))

        tk.Button(
            btn_row,
            text="Şimdilik Geç (Kilitli Devam Et)",
            command=self.destroy,
            bg="#334155",
            fg="#F8FAFC",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.LEFT)

        tk.Button(
            btn_row,
            text="Şifreli Kasayı Oluştur",
            command=self._handle_create,
            bg="#16A34A",
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

    def _toggle_visibility(self) -> None:
        """Toggles masked vs visible password characters."""
        mask = "" if self._show_var.get() else "*"
        self._pw_entry.configure(show=mask)
        self._confirm_entry.configure(show=mask)

    def _handle_create(self) -> None:
        """Validates password strength, imports plaintext profile if present, and saves."""
        pw = self._pw_entry.get()
        confirm = self._confirm_entry.get()

        if len(pw) < MIN_PASSWORD_LENGTH:
            self._status_label.configure(
                text=f"Ana parola en az {MIN_PASSWORD_LENGTH} karakter olmalıdır."
            )
            return

        if pw != confirm:
            self._status_label.configure(text="Girilen parolalar eşleşmiyor.")
            return

        imported_profile = self._vault.import_and_shred_legacy_plaintext()
        migrated = imported_profile is not None
        profile = imported_profile if imported_profile is not None else DeviceProfile()

        self._vault.initialize_vault(pw, profile)
        self._on_initialized(profile, migrated)
        self.destroy()


class VaultUnlockDialog(tk.Toplevel):
    """Modal dialog for unlocking an existing encrypted device vault."""

    def __init__(
        self,
        parent: tk.Tk,
        vault: EncryptedVaultRepository,
        on_unlocked: Callable[[DeviceProfile], None],
    ) -> None:
        super().__init__(parent)
        self.title("Şifreli Cihaz Kasasını Aç")
        self.geometry("460x260")
        self.minsize(420, 240)
        self.resizable(True, True)
        self.configure(bg="#181A1F")
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._on_unlocked = on_unlocked
        self._show_var = tk.BooleanVar(value=False)

        container = tk.Frame(self, bg="#181A1F", padx=18, pady=16)
        container.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            container,
            text="Cihaz Kasasının Kilidini Aç",
            bg="#181A1F",
            fg="#F8FAFC",
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            container,
            text="IMEI numaralarına ve 2FA yedek kodlarına erişmek için ana parolanı gir.",
            bg="#181A1F",
            fg="#94A3B8",
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 12))

        self._pw_entry = tk.Entry(
            container,
            show="*",
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Segoe UI", 10),
        )
        self._pw_entry.pack(fill=tk.X, ipady=5, pady=(0, 6))
        self._pw_entry.focus_set()
        self._pw_entry.bind("<Return>", lambda _event: self._handle_unlock())

        tk.Checkbutton(
            container,
            text="Parolayı göster",
            variable=self._show_var,
            command=self._toggle_visibility,
            bg="#181A1F",
            fg="#94A3B8",
            selectcolor="#0F172A",
            activebackground="#181A1F",
            activeforeground="#F8FAFC",
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        self._status_label = tk.Label(
            container,
            text="",
            bg="#181A1F",
            fg="#F87171",
            font=("Segoe UI", 9),
            anchor="w",
        )
        self._status_label.pack(fill=tk.X, pady=(4, 6))

        btn_row = tk.Frame(container, bg="#181A1F")
        btn_row.pack(fill=tk.X, pady=(4, 0))

        tk.Button(
            btn_row,
            text="Kilitli Devam Et",
            command=self.destroy,
            bg="#334155",
            fg="#F8FAFC",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.LEFT)

        tk.Button(
            btn_row,
            text="Kasayı Aç",
            command=self._handle_unlock,
            bg="#2563EB",
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

    def _toggle_visibility(self) -> None:
        """Toggles masked vs visible password characters."""
        mask = "" if self._show_var.get() else "*"
        self._pw_entry.configure(show=mask)

    def _handle_unlock(self) -> None:
        """Attempts to decrypt the vault with the provided password."""
        pw = self._pw_entry.get()
        if not pw:
            self._status_label.configure(text="Lütfen ana parolanı gir.")
            return

        try:
            profile = self._vault.unlock(pw)
        except InvalidToken:
            self._pw_entry.delete(0, tk.END)
            self._status_label.configure(text="Hatalı ana parola.")
            return
        except (OSError, KeyError, TypeError, ValueError) as exc:
            self._status_label.configure(text=f"Kasa okuma hatası: {exc}")
            return

        self._on_unlocked(profile)
        self.destroy()


class ChangePasswordDialog(tk.Toplevel):
    """Modal dialog for rotating the vault master password."""

    def __init__(
        self,
        parent: tk.Tk,
        vault: EncryptedVaultRepository,
        current_profile: DeviceProfile,
        on_changed: Callable[[], object],
    ) -> None:
        super().__init__(parent)
        self.title("Ana Parolayı Değiştir")
        self.geometry("460x350")
        self.minsize(420, 330)
        self.resizable(True, True)
        self.configure(bg="#181A1F")
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._profile = current_profile
        self._on_changed = on_changed

        container = tk.Frame(self, bg="#181A1F", padx=18, pady=16)
        container.pack(fill=tk.BOTH, expand=True)

        self._current_entry = self._add_pw_field(container, "Mevcut Ana Parola:")
        self._new_entry = self._add_pw_field(
            container,
            f"Yeni Ana Parola (en az {MIN_PASSWORD_LENGTH} karakter):",
        )
        self._confirm_entry = self._add_pw_field(container, "Yeni Ana Parola (Tekrar):")
        self._confirm_entry.bind("<Return>", lambda _event: self._handle_change())

        self._status_label = tk.Label(
            container,
            text="",
            bg="#181A1F",
            fg="#F87171",
            font=("Segoe UI", 9),
            anchor="w",
        )
        self._status_label.pack(fill=tk.X, pady=(6, 8))

        btn_row = tk.Frame(container, bg="#181A1F")
        btn_row.pack(fill=tk.X)

        tk.Button(
            btn_row,
            text="İptal",
            command=self.destroy,
            bg="#334155",
            fg="#F8FAFC",
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT, padx=(8, 0))

        tk.Button(
            btn_row,
            text="Parolayı Güncelle",
            command=self._handle_change,
            bg="#16A34A",
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        self._current_entry.focus_set()

    @staticmethod
    def _add_pw_field(parent: tk.Frame, label_text: str) -> tk.Entry:
        """Creates a labeled masked password entry."""
        tk.Label(
            parent,
            text=label_text,
            bg="#181A1F",
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X, pady=(4, 2))

        entry = tk.Entry(
            parent,
            show="*",
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Segoe UI", 10),
        )
        entry.pack(fill=tk.X, ipady=4)
        return entry

    def _handle_change(self) -> None:
        """Verifies current credentials and re-encrypts the vault with a new key."""
        current_pw = self._current_entry.get()
        new_pw = self._new_entry.get()
        confirm_pw = self._confirm_entry.get()

        if len(new_pw) < MIN_PASSWORD_LENGTH:
            self._status_label.configure(
                text=f"Yeni parola en az {MIN_PASSWORD_LENGTH} karakter olmalıdır."
            )
            return

        if new_pw != confirm_pw:
            self._status_label.configure(text="Yeni parolalar eşleşmiyor.")
            return

        try:
            self._vault.change_master_password(current_pw, new_pw, self._profile)
        except InvalidToken:
            self._status_label.configure(text="Mevcut ana parola hatalı.")
            return

        self._on_changed()
        self.destroy()


class ProfileEditorDialog(tk.Toplevel):
    """Modal dialog for editing, ADB-autofilling, and encrypting device credentials."""

    def __init__(
        self,
        parent: tk.Tk,
        profile: DeviceProfile,
        on_save: Callable[[DeviceProfile], None],
    ) -> None:
        super().__init__(parent)
        self.title("Cihaz Bilgilerini Düzenle (Şifreli Kasa)")
        self.geometry("580x610")
        self.minsize(520, 560)
        self.resizable(True, True)
        self.configure(bg="#181A1F")
        self.transient(parent)
        self.grab_set()

        self._on_save = on_save
        self._adb_reader = AdbDeviceReader()

        container = tk.Frame(self, bg="#181A1F", padx=16, pady=14)
        container.pack(fill=tk.BOTH, expand=True)

        adb_bar = tk.Frame(container, bg="#232730", padx=10, pady=8)
        adb_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            adb_bar,
            text="USB ile bağlı Android telefondan model ve IMEI bilgilerini otomatik aktar:",
            bg="#232730",
            fg="#CBD5E1",
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._adb_btn = tk.Button(
            adb_bar,
            text="ADB ile Telefondan Çek",
            command=self._start_adb_fetch,
            bg="#2563EB",
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=5,
            cursor="hand2",
        )
        self._adb_btn.pack(side=tk.RIGHT)

        self._adb_status_label = tk.Label(
            container,
            text="",
            bg="#181A1F",
            fg="#38BDF8",
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=540,
            justify=tk.LEFT,
        )
        self._adb_status_label.pack(fill=tk.X, pady=(0, 4))

        self._model_var = tk.StringVar(value=profile.device_model)
        self._phone_var = tk.StringVar(value=profile.phone_number)
        self._imei1_var = tk.StringVar(value=profile.imei_1)
        self._imei2_var = tk.StringVar(value=profile.imei_2)
        self._hotline_var = tk.StringVar(value=profile.operator_hotline)

        self._add_field(container, "Cihaz Modeli:", self._model_var)
        self._add_field(container, "Telefon Numarası:", self._phone_var)
        self._add_field(container, "IMEI 1 (Birincil SIM Yuvası):", self._imei1_var)
        self._add_field(container, "IMEI 2 (İkincil SIM / eSIM):", self._imei2_var)
        self._add_field(container, "Operatör Acil Hatları:", self._hotline_var)

        tk.Label(
            container,
            text="Google 8 Haneli Yedek Kodlar (Her satıra bir kod yazın):",
            bg="#181A1F",
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X, pady=(8, 2))

        self._codes_text = tk.Text(
            container,
            height=6,
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Consolas", 10),
            padx=8,
            pady=6,
        )
        self._codes_text.pack(fill=tk.BOTH, expand=True)
        self._codes_text.insert("1.0", "\n".join(profile.backup_codes))

        button_row = tk.Frame(container, bg="#181A1F")
        button_row.pack(fill=tk.X, pady=(14, 0))

        tk.Button(
            button_row,
            text="İptal",
            command=self.destroy,
            bg="#334155",
            fg="#F8FAFC",
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT, padx=(8, 0))

        tk.Button(
            button_row,
            text="Şifrele ve Kaydet",
            command=self._handle_save,
            bg="#16A34A",
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

    def _add_field(self, parent: tk.Frame, label_text: str, variable: tk.StringVar) -> None:
        """Renders a labeled input row."""
        tk.Label(
            parent,
            text=label_text,
            bg="#181A1F",
            fg="#E2E8F0",
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X, pady=(4, 1))

        tk.Entry(
            parent,
            textvariable=variable,
            bg="#232730",
            fg="#F8FAFC",
            insertbackground="#F8FAFC",
            relief=tk.FLAT,
            font=("Consolas", 10),
        ).pack(fill=tk.X, ipady=4)

    def _start_adb_fetch(self) -> None:
        """Launches a background worker thread to query device info via ADB."""
        self._adb_btn.configure(state=tk.DISABLED, text="Okunuyor...")
        self._adb_status_label.configure(
            fg="#38BDF8",
            text="ADB üzerinden bağlı cihaz sorgulanıyor...",
        )

        worker = threading.Thread(target=self._run_adb_worker, daemon=True)
        worker.start()

    def _run_adb_worker(self) -> None:
        """Executes ADB queries off the UI thread and schedules UI updates."""
        try:
            info = self._adb_reader.read_connected_device()
        except (RuntimeError, TimeoutError, subprocess.TimeoutExpired, OSError) as exc:
            self.after(0, lambda msg=str(exc): self._on_adb_error(msg))
            return

        self.after(0, lambda data=info: self._on_adb_success(data))

    def _on_adb_error(self, error_message: str) -> None:
        """Displays ADB connection or permission diagnostics in the dialog."""
        if not self.winfo_exists():
            return
        self._adb_btn.configure(state=tk.NORMAL, text="ADB ile Telefondan Çek")
        self._adb_status_label.configure(fg="#F87171", text=error_message)

    def _on_adb_success(self, info: AdbDeviceInfo) -> None:
        """Populates form fields with retrieved hardware identifiers."""
        if not self.winfo_exists():
            return
        self._adb_btn.configure(state=tk.NORMAL, text="ADB ile Telefondan Çek")

        populated_fields: list[str] = []
        if info.device_model:
            self._model_var.set(info.device_model)
            populated_fields.append("Model")
        if info.imei_1:
            self._imei1_var.set(info.imei_1)
            populated_fields.append("IMEI 1")
        if info.imei_2:
            self._imei2_var.set(info.imei_2)
            populated_fields.append("IMEI 2")
        if info.phone_number:
            self._phone_var.set(info.phone_number)
            populated_fields.append("Telefon No")

        summary = ", ".join(populated_fields) if populated_fields else "Veri"
        self._adb_status_label.configure(
            fg="#34D399",
            text=f"Aktarılan alanlar: {summary}. Kalıcı olması için 'Şifrele ve Kaydet' butonuna basın.",
        )

    def _handle_save(self) -> None:
        """Collects updated profile values and passes them to the main window."""
        raw_codes = self._codes_text.get("1.0", tk.END).splitlines()
        cleaned_codes = [line.strip() for line in raw_codes if line.strip()]
        imei_1 = self._imei1_var.get().strip()
        imei_2 = self._imei2_var.get().strip()
        phone_number = self._phone_var.get().strip()

        for imei in (imei_1, imei_2):
            if imei and (not imei.isdigit() or not 14 <= len(imei) <= 16):
                messagebox.showwarning(
                    "Geçersiz IMEI",
                    "IMEI alanları yalnızca rakam içermeli ve 14–16 haneli olmalıdır.",
                )
                return
        if phone_number:
            phone_digits = "".join(ch for ch in phone_number if ch.isdigit())
            if len(phone_digits) < 10:
                messagebox.showwarning(
                    "Geçersiz Telefon Numarası",
                    "Telefon numarası en az 10 rakam içermelidir.",
                )
                return

        updated = DeviceProfile(
            device_model=self._model_var.get().strip(),
            phone_number=phone_number,
            imei_1=imei_1,
            imei_2=imei_2,
            operator_hotline=self._hotline_var.get().strip(),
            backup_codes=cleaned_codes,
        )
        self._on_save(updated)
        self.destroy()


class TheftResponseApp:
    """Main Tkinter desktop application orchestrating the response workflow."""

    BG_DARK = "#111318"
    BG_CARD = "#1B1F27"
    BG_HEADER = "#1E2430"
    FG_PRIMARY = "#F8FAFC"
    FG_SECONDARY = "#94A3B8"
    ACCENT_RED = "#DC2626"
    ACCENT_BLUE = "#2563EB"
    ACCENT_GREEN = "#16A34A"
    ACCENT_AMBER = "#D97706"

    def __init__(self, root: tk.Tk, initial_dry_run: bool = False) -> None:
        self.root = root
        self.root.title("Android Hırsızlık Acil Müdahale Konsolu")
        self.root.geometry("1260x840")
        self.root.minsize(1040, 680)
        self.root.configure(bg=self.BG_DARK)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        base_dir = Path(__file__).resolve().parent
        desktop_dir = Path.home() / "Desktop"
        log_dir = desktop_dir if desktop_dir.exists() else base_dir

        self._vault = EncryptedVaultRepository(
            vault_path=base_dir / "device_vault.enc",
            legacy_json_path=base_dir / "device_profile.json",
        )
        self._profile = DeviceProfile()
        self._checklist = build_default_checklist()
        self._check_vars: dict[str, tk.BooleanVar] = {}
        self._copy_buttons: list[tk.Button] = []
        self._backup_code_index = 0
        self._dry_run_var = tk.BooleanVar(value=initial_dry_run)

        self._build_layout()

        self._logger = AuditLogger(
            log_dir,
            on_entry=self._append_log_to_view,
            dry_run=initial_dry_run,
        )
        self._clipboard = ClipboardManager(self.root, self._logger)
        self._sync_drill_mode_ui()
        self._logger.log("SİSTEM", "Konsol başlatıldı.")
        self._sync_vault_ui_state()
        self.root.after(120, self._prompt_vault_access)

    def _build_layout(self) -> None:
        """Constructs the top quick-copy bar, checklist panel, and live audit log."""
        self._build_top_bar()

        body = tk.PanedWindow(
            self.root,
            orient=tk.HORIZONTAL,
            bg=self.BG_DARK,
            sashwidth=6,
            sashrelief=tk.FLAT,
        )
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        left_panel = self._build_checklist_panel(body)
        right_panel = self._build_audit_panel(body)

        body.add(left_panel, stretch="always", width=780)
        body.add(right_panel, stretch="always", width=440)

    def _build_top_bar(self) -> None:
        """Creates the emergency quick-copy, drill-mode switch, and vault-control toolbar."""
        top_frame = tk.Frame(self.root, bg=self.BG_HEADER, padx=14, pady=10)
        top_frame.pack(fill=tk.X, padx=12, pady=12)

        title_row = tk.Frame(top_frame, bg=self.BG_HEADER)
        title_row.pack(fill=tk.X)

        self._mode_badge = tk.Label(
            title_row,
            text="ACİL MÜDAHALE PLANI",
            bg=self.ACCENT_RED,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=3,
        )
        self._mode_badge.pack(side=tk.LEFT)

        self._device_banner = tk.Label(
            title_row,
            text="",
            bg=self.BG_HEADER,
            fg=self.FG_PRIMARY,
            font=("Segoe UI", 11, "bold"),
            padx=10,
        )
        self._device_banner.pack(side=tk.LEFT)

        self._progress_label = tk.Label(
            title_row,
            text="Tamamlanan: 0 / 10",
            bg=self.BG_HEADER,
            fg="#38BDF8",
            font=("Segoe UI", 10, "bold"),
        )
        self._progress_label.pack(side=tk.RIGHT)

        self._drill_toggle = tk.Checkbutton(
            title_row,
            text="Tatbikat Modu (Masaüstüne Dosya Yazmaz)",
            variable=self._dry_run_var,
            command=self._on_drill_mode_toggled,
            indicatoron=False,
            bg="#334155",
            fg=self.FG_PRIMARY,
            selectcolor=self.ACCENT_AMBER,
            activebackground="#475569",
            activeforeground="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=3,
            cursor="hand2",
        )
        self._drill_toggle.pack(side=tk.RIGHT, padx=(0, 14))

        controls_row = tk.Frame(top_frame, bg=self.BG_HEADER)
        controls_row.pack(fill=tk.X, pady=(10, 0))

        self._copy_buttons.append(
            self._create_copy_button(
                controls_row,
                "Telefon No Kopyala",
                self.ACCENT_BLUE,
                lambda: self._clipboard.copy_text("Telefon Numarası", self._profile.phone_number),
            )
        )
        self._copy_buttons.append(
            self._create_copy_button(
                controls_row,
                "IMEI 1 Kopyala",
                self.ACCENT_BLUE,
                lambda: self._clipboard.copy_text("IMEI 1", self._profile.imei_1),
            )
        )
        self._copy_buttons.append(
            self._create_copy_button(
                controls_row,
                "IMEI 2 Kopyala",
                self.ACCENT_BLUE,
                lambda: self._clipboard.copy_text("IMEI 2", self._profile.imei_2),
            )
        )
        self._copy_buttons.append(
            self._create_copy_button(
                controls_row,
                "Sıradaki 2FA Yedek Kodu",
                self.ACCENT_AMBER,
                self._copy_next_backup_code,
            )
        )

        self._lock_toggle_btn = tk.Button(
            controls_row,
            text="Kasayı Aç",
            command=self._handle_vault_toggle,
            bg=self.ACCENT_GREEN,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self._lock_toggle_btn.pack(side=tk.RIGHT, padx=(8, 0))

        self._change_pw_btn = tk.Button(
            controls_row,
            text="Parolayı Değiştir",
            command=self._open_change_password_dialog,
            bg="#334155",
            fg=self.FG_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self._change_pw_btn.pack(side=tk.RIGHT, padx=(8, 0))

        self._edit_btn = tk.Button(
            controls_row,
            text="Cihaz Bilgilerini Düzenle",
            command=self._open_profile_editor,
            bg="#334155",
            fg=self.FG_PRIMARY,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self._edit_btn.pack(side=tk.RIGHT)

        self._hotline_banner = tk.Label(
            top_frame,
            text="",
            bg=self.BG_HEADER,
            fg=self.FG_SECONDARY,
            font=("Segoe UI", 9),
            anchor="w",
        )
        self._hotline_banner.pack(fill=tk.X, pady=(8, 0))

    def _create_copy_button(
        self,
        parent: tk.Frame,
        text: str,
        bg_color: str,
        command: Callable[[], object],
    ) -> tk.Button:
        """Renders and returns a quick-copy action button."""
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        btn.pack(side=tk.LEFT, padx=(0, 8))
        return btn

    def _build_checklist_panel(self, parent: tk.PanedWindow) -> tk.Frame:
        """Creates the scrollable checklist panel on the left."""
        wrapper = tk.Frame(parent, bg=self.BG_DARK)

        canvas = tk.Canvas(wrapper, bg=self.BG_DARK, highlightthickness=0)
        scrollbar = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.BG_DARK)

        scrollable_frame.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )

        window_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(window_id, width=event.width),
        )
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._bind_mousewheel(canvas)

        current_phase = ""
        for item in self._checklist:
            if item.phase != current_phase:
                current_phase = item.phase
                tk.Label(
                    scrollable_frame,
                    text=current_phase,
                    bg=self.BG_DARK,
                    fg="#FBBF24",
                    font=("Segoe UI", 10, "bold"),
                    anchor="w",
                ).pack(fill=tk.X, pady=(12, 4), padx=4)

            self._render_checklist_card(scrollable_frame, item)

        return wrapper

    def _render_checklist_card(self, parent: tk.Frame, item: ChecklistItem) -> None:
        """Renders an individual step card with checkbox, instructions, and URL button."""
        card = tk.Frame(parent, bg=self.BG_CARD, padx=12, pady=10)
        card.pack(fill=tk.X, pady=4, padx=4)

        header_row = tk.Frame(card, bg=self.BG_CARD)
        header_row.pack(fill=tk.X)

        var = tk.BooleanVar(value=item.completed)
        self._check_vars[item.item_id] = var

        chk = tk.Checkbutton(
            header_row,
            text=f"[{item.item_id}] {item.title}",
            variable=var,
            command=lambda current=item, state_var=var: self._on_step_toggled(current, state_var),
            bg=self.BG_CARD,
            fg=self.FG_PRIMARY,
            selectcolor="#0F172A",
            activebackground=self.BG_CARD,
            activeforeground=self.FG_PRIMARY,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        chk.pack(side=tk.LEFT, anchor="w")

        if item.action_url and item.action_label:
            tk.Button(
                header_row,
                text=item.action_label,
                command=lambda current=item: self._open_action_url(current),
                bg=self.ACCENT_GREEN,
                fg="#FFFFFF",
                font=("Segoe UI", 8, "bold"),
                relief=tk.FLAT,
                padx=10,
                pady=4,
                cursor="hand2",
            ).pack(side=tk.RIGHT)

        for detail in item.details:
            tk.Label(
                card,
                text=f"• {detail}",
                bg=self.BG_CARD,
                fg=self.FG_SECONDARY,
                font=("Segoe UI", 9),
                anchor="w",
                justify=tk.LEFT,
                wraplength=700,
            ).pack(fill=tk.X, padx=(24, 0), pady=(2, 0))

    def _build_audit_panel(self, parent: tk.PanedWindow) -> tk.Frame:
        """Creates the live timestamped audit log panel on the right."""
        panel = tk.Frame(parent, bg=self.BG_CARD, padx=12, pady=10)

        header = tk.Frame(panel, bg=self.BG_CARD)
        header.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            header,
            text="ZAMAN DAMGALI OLAY KAYDI (TUTANAK)",
            bg=self.BG_CARD,
            fg=self.FG_PRIMARY,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT)

        tk.Button(
            header,
            text="Dosyayı Aç",
            command=self._open_log_file,
            bg="#334155",
            fg=self.FG_PRIMARY,
            font=("Segoe UI", 8, "bold"),
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        self._log_view = scrolledtext.ScrolledText(
            panel,
            bg="#0B0D11",
            fg="#34D399",
            font=("Consolas", 9),
            relief=tk.FLAT,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self._log_view.pack(fill=tk.BOTH, expand=True)

        note_row = tk.Frame(panel, bg=self.BG_CARD)
        note_row.pack(fill=tk.X, pady=(8, 0))

        self._note_entry = tk.Entry(
            note_row,
            bg="#0F172A",
            fg=self.FG_PRIMARY,
            insertbackground=self.FG_PRIMARY,
            relief=tk.FLAT,
            font=("Segoe UI", 9),
        )
        self._note_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 6))
        self._note_entry.bind("<Return>", lambda _event: self._add_custom_note())

        tk.Button(
            note_row,
            text="Not / Takip No Ekle",
            command=self._add_custom_note,
            bg=self.ACCENT_BLUE,
            fg="#FFFFFF",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=10,
            pady=5,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

        return panel

    def _bind_mousewheel(self, canvas: tk.Canvas) -> None:
        """Enables cross-platform mousewheel scrolling on Windows and Linux."""

        def _on_mousewheel(event: tk.Event) -> None:
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _on_linux_up(_event: tk.Event) -> None:
            canvas.yview_scroll(-1, "units")

        def _on_linux_down(_event: tk.Event) -> None:
            canvas.yview_scroll(1, "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", _on_linux_up)
        canvas.bind_all("<Button-5>", _on_linux_down)

    def _on_drill_mode_toggled(self) -> None:
        """Switches between live incident logging and isolated drill mode."""
        enabled = self._dry_run_var.get()
        self._logger.set_dry_run(enabled)
        self._sync_drill_mode_ui()

        if enabled:
            self._logger.log(
                "SİSTEM",
                "Tatbikat modu etkinleştirildi. Masaüstüne resmi tutanak dosyası yazılmayacak.",
            )
        else:
            self._reset_checklist_state()
            self._backup_code_index = 0
            self._logger.log(
                "SİSTEM",
                "Tatbikat modu kapatıldı; kontrol listesi sıfırlandı ve resmi tutanak kaydı aktif.",
            )

    def _sync_drill_mode_ui(self) -> None:
        """Updates top-bar badges and switch labels to reflect active mode."""
        if self._dry_run_var.get():
            self._mode_badge.configure(text="TATBİKAT MODU AKTİF", bg=self.ACCENT_AMBER)
            self._drill_toggle.configure(text="Tatbikat Modu: AÇIK (Test)")
        else:
            self._mode_badge.configure(text="ACİL MÜDAHALE PLANI", bg=self.ACCENT_RED)
            self._drill_toggle.configure(text="Tatbikat Modu: KAPALI")

    def _reset_checklist_state(self) -> None:
        """Clears all checklist checkboxes and resets the completion counter."""
        for item in self._checklist:
            item.completed = False
            var = self._check_vars.get(item.item_id)
            if var is not None:
                var.set(False)
        self._update_progress_counter()

    def _prompt_vault_access(self) -> None:
        """Launches setup or unlock dialog based on whether device_vault.enc exists."""
        if not self._vault.exists:
            VaultSetupDialog(self.root, self._vault, self._on_vault_initialized)
        else:
            VaultUnlockDialog(self.root, self._vault, self._on_vault_unlocked)

    def _on_vault_initialized(self, profile: DeviceProfile, migrated: bool) -> None:
        """Handles state transition after initial encrypted vault creation."""
        self._profile = profile
        self._backup_code_index = 0
        self._sync_vault_ui_state()
        if migrated:
            self._logger.log(
                "GÜVENLİK",
                "Eski düz metin device_profile.json şifreli kasaya aktarıldı ve sıfır yazılarak silindi.",
            )
        else:
            self._logger.log("GÜVENLİK", "Yeni şifreli cihaz kasası oluşturuldu.")

    def _on_vault_unlocked(self, profile: DeviceProfile) -> None:
        """Handles state transition when the encrypted vault is unlocked."""
        self._profile = profile
        self._backup_code_index = 0
        self._sync_vault_ui_state()
        self._logger.log("GÜVENLİK", f"'{profile.device_model}' için şifreli kasa açıldı.")

    def _handle_vault_toggle(self) -> None:
        """Locks the vault if unlocked, or opens the setup/unlock dialog if locked."""
        if self._vault.is_unlocked:
            self._vault.lock()
            self._profile = DeviceProfile()
            self._backup_code_index = 0
            self._sync_vault_ui_state()
            self._logger.log("GÜVENLİK", "Kasa kilitlendi ve şifreleme anahtarı bellekten silindi.")
        else:
            self._prompt_vault_access()

    def _sync_vault_ui_state(self) -> None:
        """Enables or disables sensitive controls according to vault lock state."""
        unlocked = self._vault.is_unlocked
        widget_state = tk.NORMAL if unlocked else tk.DISABLED

        for btn in self._copy_buttons:
            btn.configure(state=widget_state)
        self._edit_btn.configure(state=widget_state)
        self._change_pw_btn.configure(state=widget_state)

        if unlocked:
            self._lock_toggle_btn.configure(text="Kasayı Kilitle", bg=self.ACCENT_RED)
            self._device_banner.configure(
                text=f"{self._profile.device_model}  |  {self._profile.phone_number}  [KASA AÇIK]"
            )
            self._hotline_banner.configure(text=f"Operatör Hatları: {self._profile.operator_hotline}")
        else:
            action_text = "Kasayı Aç" if self._vault.exists else "Kasayı Kur"
            self._lock_toggle_btn.configure(text=action_text, bg=self.ACCENT_GREEN)
            self._device_banner.configure(
                text="KASA KİLİTLİ  |  IMEI ve 2FA kodlarını kopyalamak için kasayı açın"
            )
            self._hotline_banner.configure(
                text="Operatör Hatları: Turkcell: 0532 532 00 00 | Türk Telekom: 444 1 444 | Vodafone: 0542 542 00 00"
            )

    def _on_step_toggled(self, item: ChecklistItem, state_var: tk.BooleanVar) -> None:
        """Records step completion or rollback with an exact timestamp."""
        item.completed = state_var.get()
        status = "TAMAMLANDI" if item.completed else "GERİ ALINDI"
        self._logger.log(status, f"{item.item_id} - {item.title}")
        self._update_progress_counter()

    def _open_action_url(self, item: ChecklistItem) -> None:
        """Opens the target recovery portal in the default browser and logs it."""
        if not item.action_url:
            return
        webbrowser.open_new_tab(item.action_url)
        self._logger.log("TARAYICI", f"{item.item_id} - {item.action_url} adresi açıldı.")

    def _copy_next_backup_code(self) -> None:
        """Copies the next available Google 8-digit backup code in rotation."""
        if not self._vault.is_unlocked:
            return

        codes = self._profile.backup_codes
        if not codes:
            messagebox.showwarning(
                "Yedek Kod Yok",
                "Lütfen 'Cihaz Bilgilerini Düzenle' penceresinden 8 haneli Google yedek kodlarını ekleyin.",
            )
            return

        code = codes[self._backup_code_index % len(codes)]
        slot_number = (self._backup_code_index % len(codes)) + 1
        self._backup_code_index += 1
        self._clipboard.copy_text(f"Google Yedek Kod #{slot_number}", code, mask_in_log=True)

    def _add_custom_note(self) -> None:
        """Logs operator reference numbers, BTK tracking IDs, or police station notes."""
        text = self._note_entry.get().strip()
        if not text:
            return
        self._logger.log("NOT", text)
        self._note_entry.delete(0, tk.END)

    def _open_log_file(self) -> None:
        """Opens the official audit log file or notifies when drill mode is active."""
        if self._logger.is_dry_run or not self._logger.has_official_file:
            messagebox.showinfo(
                "Resmi Tutanak Dosyası Yok",
                "Tatbikat modu aktif veya henüz resmi bir müdahale adımı kaydedilmediği için "
                "masaüstünde tutanak dosyası oluşturulmadı.",
            )
            return
        webbrowser.open(self._logger.log_path.as_uri())

    def _open_profile_editor(self) -> None:
        """Launches the modal dialog to edit local device identifiers."""
        if not self._vault.is_unlocked:
            return
        ProfileEditorDialog(self.root, self._profile, self._save_updated_profile)

    def _open_change_password_dialog(self) -> None:
        """Launches the modal dialog to rotate the vault master password."""
        if not self._vault.is_unlocked:
            return
        ChangePasswordDialog(
            self.root,
            self._vault,
            self._profile,
            lambda: self._logger.log("GÜVENLİK", "Kasa ana parolası yeni tuz (salt) ile güncellendi."),
        )

    def _save_updated_profile(self, updated: DeviceProfile) -> None:
        """Encrypts and persists updated profile data and refreshes UI banners."""
        self._profile = updated
        self._vault.save(updated)
        self._backup_code_index = 0
        self._sync_vault_ui_state()
        self._logger.log("GÜVENLİK", f"'{updated.device_model}' cihaz bilgileri şifrelenerek kaydedildi.")

    def _update_progress_counter(self) -> None:
        """Updates the completed step counter in the header."""
        done = sum(1 for item in self._checklist if item.completed)
        total = len(self._checklist)
        self._progress_label.configure(text=f"Tamamlanan: {done} / {total}")

    def _append_log_to_view(self, entry: str) -> None:
        """Appends a formatted audit entry to the read-only log widget."""
        self._log_view.configure(state=tk.NORMAL)
        self._log_view.insert(tk.END, entry)
        self._log_view.see(tk.END)
        self._log_view.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        """Wipes encryption keys from memory before exiting the application."""
        self._vault.lock()
        self.root.destroy()


def main() -> None:
    """Application entry point."""
    initial_dry_run = "--dry-run" in sys.argv
    root = tk.Tk()
    TheftResponseApp(root, initial_dry_run=initial_dry_run)
    root.mainloop()


if __name__ == "__main__":
    main()