from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def _read_dvr_config_smali_source() -> str:
    return (ROOT / "tools/apk-re/sidecars/smali/DvrConfigProbe.smali").read_text(
        encoding="utf-8"
    )


def test_dvr_config_smali_exits_nonzero_on_usage_error() -> None:
    source = _read_dvr_config_smali_source()

    assert (
        'const-string v1, "[dvr-config-sidecar] usage: '
        '<ip> <port> <user> <password> <command> <channel> <outSize>"\n\n'
        "    invoke-virtual {v0, v1}, "
        "Ljava/io/PrintStream;->println(Ljava/lang/String;)V\n\n"
        "    const/4 v0, 0x2\n\n"
        "    invoke-static {v0}, Ljava/lang/System;->exit(I)V\n\n"
        "    return-void"
    ) in source


def test_dvr_config_smali_exits_on_neutral_login_failure() -> None:
    source = _read_dvr_config_smali_source()

    match = re.search(
        r"invoke-static \{v2, v3, v4, v5, v11\}, "
        r"Lcom/videogo/add/device/HCNETUtil;->r\(.*?\)I\s+"
        r"move-result v13\s+"
        r".*?"
        r"if-gez v13, :neutral_login_ok\s+"
        r"const/4 v0, 0x1\s+"
        r"invoke-static \{v0\}, Ljava/lang/System;->exit\(I\)V\s+"
        r"return-void\s+"
        r":neutral_login_ok\s+"
        r"const/4 v14, 0x0\s+"
        r"new-instance v0, Lcom/neutral/netsdk/NET_DVR_USER_V30;",
        source,
        re.DOTALL,
    )

    assert match is not None


def test_dvr_config_java_reference_exits_on_neutral_login_failure() -> None:
    source = (ROOT / "tools/apk-re/sidecars/DvrConfigProbe.java").read_text(
        encoding="utf-8"
    )

    assert (
        "if (neutralLoginId < 0) {\n"
        "                System.exit(1);\n"
        "                return;\n"
        "            }\n"
        "            boolean ok = false;\n"
        "            com.neutral.netsdk.NET_DVR_USER_V30 userConfig ="
    ) in source


def test_dvr_config_smali_exits_on_jna_login_failure() -> None:
    source = _read_dvr_config_smali_source()

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
