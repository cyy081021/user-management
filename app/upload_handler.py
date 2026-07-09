"""
上传处理模块 — 文件类型校验、内容验证、安全存储
"""
import os
import uuid
import logging
from pathlib import Path

from PIL import Image
from werkzeug.utils import secure_filename

import magic

logger = logging.getLogger(__name__)

# 允许的扩展名（仅安全图片类型）
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}

# 允许的 MIME 类型（与扩展名对应）
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
}

# 上传文件存储路径（项目根目录下 uploads/，不放在 static/ 下）
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"


def _ensure_upload_dir():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _suffix_from_mime(mime):
    """MIME 类型转文件后缀"""
    return {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }.get(mime, "")


def validate_upload(file_storage):
    """
    校验上传文件，返回 (成功?, 错误消息, 保存信息字典)
    保存信息: {safe_name, display_name, mime, size, path, url}
    """
    # --- 1. 基本检查 ---
    if not file_storage or not file_storage.filename:
        return False, "请选择文件", None

    original_name = file_storage.filename
    logger.info("上传请求: filename=%s, content_type=%s", original_name, file_storage.content_type)

    # --- 2. 检查文件大小（应用层二次校验）---
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)
    max_size = 16 * 1024 * 1024  # 16MB
    if size > max_size:
        return False, f"文件过大（最大 {max_size // 1024 // 1024}MB）", None
    if size == 0:
        return False, "文件为空", None

    # --- 3. 原始文件名安全检查 ---
    safe_display = secure_filename(original_name)
    if not safe_display:
        return False, "文件名不合法", None

    # --- 4. 检查扩展名 ---
    ext = os.path.splitext(original_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"不允许的文件类型（仅支持: {', '.join(ALLOWED_EXTENSIONS)}）", None

    # --- 5. 读取文件头，使用 magic 验证真实类型 ---
    header = file_storage.read(2048)
    file_storage.seek(0)
    detected_mime = magic.from_buffer(header, mime=True)
    logger.info("Magic 检测 MIME: %s", detected_mime)

    if detected_mime not in ALLOWED_MIME_TYPES:
        return False, f"文件内容不是有效图片（检测到: {detected_mime}）", None

    # --- 6. 扩展名与真实类型一致性校验 ---
    expected_ext = _suffix_from_mime(detected_mime)
    if ext != expected_ext:
        return False, f"文件扩展名与真实类型不匹配（.{ext} → {detected_mime}）", None

    # --- 7. 用 Pillow 验证并重新编码图片（去除恶意 payload 和元数据）---
    try:
        img = Image.open(file_storage)
        # 验证图片完整性（会触发完整解码）
        img.verify()
    except Exception as e:
        return False, f"图片格式无效: {e}", None

    # verify 后需要重新打开
    file_storage.seek(0)
    try:
        img = Image.open(file_storage)
        # 转为 RGB（去除 RGBA 的透明通道、调色板等）
        if img.mode in ("RGBA", "LA", "P", "PA"):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")
    except Exception as e:
        return False, f"图片处理失败: {e}", None

    # --- 8. 生成安全的存储文件名 ---
    _ensure_upload_dir()
    while True:
        safe_name = f"{uuid.uuid4().hex}{expected_ext}"
        save_path = UPLOAD_DIR / safe_name
        if not save_path.exists():  # 防止同名覆盖
            break

    # --- 9. 重新编码保存（去除元数据、EXIF、潜在 payload）---
    try:
        save_format = detected_mime.split("/")[1].upper()
        if save_format == "JPEG":
            save_format = "JPEG"
        elif save_format == "PNG":
            save_format = "PNG"
        elif save_format == "GIF":
            save_format = "GIF"
        elif save_format == "WEBP":
            save_format = "WEBP"

        # 不带任何额外参数保存，去除所有元数据
        img.save(str(save_path), format=save_format)
    except Exception as e:
        return False, f"图片保存失败: {e}", None

    file_url = f"/uploads/{safe_name}"
    result = {
        "safe_name": safe_name,
        "display_name": safe_display,
        "mime": detected_mime,
        "size": save_path.stat().st_size,
        "path": str(save_path),
        "url": file_url,
    }
    logger.info("上传成功: %s → %s (%s, %d bytes)", safe_display, safe_name, detected_mime, result["size"])
    return True, "上传成功", result
