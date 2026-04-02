"""
Cloudflare Email Routing + IMAP 邮箱服务
通过随机虚拟邮箱地址配合 Cloudflare 转发，最终从单个真实邮箱中读取验证码。
"""

import email
import imaplib
import logging
import random
import re
import string
import time
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, List, Optional

from .base import BaseEmailService
from ..config.constants import (
    EmailServiceType,
    OPENAI_EMAIL_SENDERS,
    OTP_CODE_PATTERN,
    OTP_CODE_SEMANTIC_PATTERN,
)

logger = logging.getLogger(__name__)


class CloudflareForwardImapService(BaseEmailService):
    """Cloudflare 转发 + IMAP 虚拟邮箱验证码服务"""

    DEFAULT_RECIPIENT_HEADERS = [
        "Delivered-To",
        "X-Envelope-To",
        "To",
        "X-Original-To",
    ]

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        super().__init__(EmailServiceType.CLOUDFLARE_FORWARD_IMAP, name)

        cfg = config or {}
        required_keys = ["host", "real_email", "password", "domains"]
        missing_keys = [key for key in required_keys if not cfg.get(key)]
        if missing_keys:
            raise ValueError(f"缺少必需配置: {missing_keys}")

        self.host: str = str(cfg["host"]).strip()
        self.port: int = int(cfg.get("port", 993))
        self.use_ssl: bool = bool(cfg.get("use_ssl", True))
        self.real_email: str = str(cfg["real_email"]).strip()
        self.password: str = str(cfg["password"])
        self.folder: str = str(cfg.get("folder") or "INBOX").strip() or "INBOX"
        self.timeout: int = int(cfg.get("timeout", 30))
        self.max_retries: int = int(cfg.get("max_retries", 3))
        self.poll_interval: int = max(1, int(cfg.get("poll_interval", 3)))
        self.require_openai_sender: bool = bool(cfg.get("require_openai_sender", True))
        self.mark_seen_on_match: bool = bool(cfg.get("mark_seen_on_match", True))
        self.domains: List[str] = self._normalize_domains(cfg.get("domains"))
        self.recipient_headers_priority: List[str] = self._normalize_recipient_headers(
            cfg.get("recipient_headers_priority")
        )

        if not self.domains:
            raise ValueError("缺少可用域名配置")

    def _normalize_domains(self, domains: Any) -> List[str]:
        if isinstance(domains, str):
            raw_items = re.split(r"[\n,]+", domains)
        elif isinstance(domains, list):
            raw_items = domains
        else:
            raw_items = []

        normalized: List[str] = []
        for item in raw_items:
            value = str(item or "").strip().lstrip("@")
            if value and value not in normalized:
                normalized.append(value)
        return normalized

    def _normalize_recipient_headers(self, headers: Any) -> List[str]:
        if isinstance(headers, str):
            raw_items = re.split(r"[\n,]+", headers)
        elif isinstance(headers, list):
            raw_items = headers
        else:
            raw_items = self.DEFAULT_RECIPIENT_HEADERS

        normalized: List[str] = []
        for item in raw_items:
            value = str(item or "").strip()
            if value and value not in normalized:
                normalized.append(value)
        return normalized or list(self.DEFAULT_RECIPIENT_HEADERS)

    def _generate_local_part(self) -> str:
        first = random.choice(string.ascii_lowercase)
        rest = "".join(random.choices(string.ascii_lowercase + string.digits, k=9))
        return f"{first}{rest}"

    def _connect(self) -> imaplib.IMAP4:
        if self.use_ssl:
            mail = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            mail = imaplib.IMAP4(self.host, self.port)
            mail.starttls()
        mail.login(self.real_email, self.password)
        return mail

    def _decode_str(self, value: Any) -> str:
        if value is None:
            return ""
        parts = decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)

    def _get_text_body(self, msg) -> str:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_type() != "text/plain":
                    continue
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(charset, errors="replace")
        else:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(charset, errors="replace")
        return body

    def _is_openai_sender(self, from_addr: str) -> bool:
        from_lower = from_addr.lower()
        for sender in OPENAI_EMAIL_SENDERS:
            if sender in from_lower:
                return True
        return False

    def _extract_otp(self, text: str, pattern: Optional[str] = None) -> Optional[str]:
        semantic_match = re.search(OTP_CODE_SEMANTIC_PATTERN, text, re.IGNORECASE)
        if semantic_match:
            return semantic_match.group(1)

        target_pattern = pattern or OTP_CODE_PATTERN
        simple_match = re.search(target_pattern, text)
        if simple_match:
            return simple_match.group(1)
        return None

    def _extract_recipient_addresses(self, msg, header_name: str) -> List[str]:
        values = msg.get_all(header_name, [])
        recipients: List[str] = []

        for value in values:
            decoded_value = self._decode_str(value)
            parsed_addresses = [
                addr.strip().lower() for _, addr in getaddresses([decoded_value]) if addr
            ]
            if parsed_addresses:
                for address in parsed_addresses:
                    if address not in recipients:
                        recipients.append(address)
                continue

            fallback_addresses = re.findall(
                r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+",
                decoded_value,
            )
            for address in fallback_addresses:
                normalized = address.strip().lower()
                if normalized and normalized not in recipients:
                    recipients.append(normalized)

        return recipients

    def _match_target_email(self, msg, target_email: str) -> bool:
        target = str(target_email or "").strip().lower()
        if not target:
            return False

        for header_name in self.recipient_headers_priority:
            recipients = self._extract_recipient_addresses(msg, header_name)
            if target in recipients:
                return True
        return False

    def _parse_message_timestamp(self, msg) -> Optional[float]:
        date_header = msg.get("Date")
        if not date_header:
            return None
        try:
            return parsedate_to_datetime(date_header).timestamp()
        except Exception:
            return None

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        request_config = config or {}
        local_part = str(request_config.get("name") or self._generate_local_part()).strip()
        domain = str(request_config.get("domain") or random.choice(self.domains)).strip().lstrip("@")
        address = f"{local_part}@{domain}"

        self.update_status(True)
        return {
            "email": address,
            "service_id": address,
            "id": address,
            "created_at": time.time(),
        }

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 60,
        pattern: str = None,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        start_time = time.time()
        seen_ids: set = set()
        mail = None
        search_timeout = int(timeout or self.timeout or 60)

        try:
            mail = self._connect()
            mail.select(self.folder)

            while time.time() - start_time < search_timeout:
                try:
                    status, data = mail.search(None, "UNSEEN")
                    if status != "OK" or not data or not data[0]:
                        time.sleep(self.poll_interval)
                        continue

                    msg_ids = data[0].split()
                    for msg_id in reversed(msg_ids):
                        id_str = msg_id.decode(errors="ignore")
                        if id_str in seen_ids:
                            continue
                        seen_ids.add(id_str)

                        status, msg_data = mail.fetch(msg_id, "(RFC822)")
                        if status != "OK" or not msg_data:
                            continue

                        raw = msg_data[0][1]
                        msg = email.message_from_bytes(raw)

                        if not self._match_target_email(msg, email):
                            continue

                        if otp_sent_at is not None:
                            message_ts = self._parse_message_timestamp(msg)
                            if message_ts is not None and message_ts + 1 < float(otp_sent_at):
                                continue

                        from_addr = self._decode_str(msg.get("From", ""))
                        if self.require_openai_sender and not self._is_openai_sender(from_addr):
                            continue

                        body = self._get_text_body(msg)
                        code = self._extract_otp(body, pattern=pattern)
                        if code:
                            if self.mark_seen_on_match:
                                mail.store(msg_id, "+FLAGS", "\\Seen")
                            self.update_status(True)
                            logger.info(f"Cloudflare Forward IMAP 获取验证码成功: {code}")
                            return code

                except imaplib.IMAP4.error as e:
                    logger.debug(f"Cloudflare Forward IMAP 搜索邮件失败: {e}")
                    try:
                        mail.select(self.folder)
                    except Exception:
                        pass

                time.sleep(self.poll_interval)

        except Exception as e:
            logger.warning(f"Cloudflare Forward IMAP 连接/轮询失败: {e}")
            self.update_status(False, str(e))
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        return None

    def check_health(self) -> bool:
        mail = None
        try:
            mail = self._connect()
            status, _ = mail.select(self.folder)
            return status == "OK"
        except Exception as e:
            logger.warning(f"Cloudflare Forward IMAP 健康检查失败: {e}")
            return False
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        return []

    def delete_email(self, email_id: str) -> bool:
        return True
