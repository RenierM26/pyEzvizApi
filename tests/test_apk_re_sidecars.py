from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_dvr_config_smali_exits_on_jna_login_failure() -> None:
    source = (
        ROOT / "tools/apk-re/sidecars/smali/DvrConfigProbe.smali"
    ).read_text(encoding="utf-8")

    match = re.search(
        r"invoke-static \{v2, v3, v4, v5, v6\}, "
        r"Lcom/videogo/add/device/HCNETUtil;->s\(.*?\)I\s+"
        r"move-result v8\s+"
        r".*?"
        r"if-gez v8, :jna_login_ok\s+"
        r"const/4 v0, 0x1\s+"
        r"invoke-static \{v0\}, Ljava/lang/System;->exit\(I\)V\s+"
        r"return-void\s+"
        r":jna_login_ok",
        source,
        re.DOTALL,
    )

    assert match is not None
