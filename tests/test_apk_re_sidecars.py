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


def test_dvr_config_java_reference_exits_on_get_failure() -> None:
    source = (ROOT / "tools/apk-re/sidecars/DvrConfigProbe.java").read_text(
        encoding="utf-8"
    )

    assert (
        "if (!ok) {\n"
        "                boolean neutralLogout = "
        "com.videogo.hcnetsdk.HCNetSDKManage.a().NET_DVR_Logout_V30"
        "(neutralLoginId);\n"
        '                System.out.println("[dvr-config-sidecar] logout=" '
        "+ neutralLogout);\n"
        '                System.out.println("[dvr-config-sidecar] done");\n'
        "                System.exit(1);\n"
        "                return;\n"
        "            }\n"
        '            System.out.println("[dvr-config-sidecar] outDump=disabled");'
    ) in source
    assert (
        "if (!ok) {\n"
        "                return;\n"
        "            }\n"
        "            if (dumpOutput) {"
    ) in source
    assert (
        "if (!ok) {\n"
        "                System.exit(1);\n"
        "            }\n"
        "        }\n"
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


def test_dvr_config_smali_exits_on_neutral_get_failure() -> None:
    source = _read_dvr_config_smali_source()

    match = re.search(
        r"invoke-virtual \{v0, v1\}, "
        r"Ljava/io/PrintStream;->println\(Ljava/lang/String;\)V\s+"
        r"if-nez v14, :neutral_get_ok\s+"
        r"invoke-static \{\}, Lcom/videogo/hcnetsdk/HCNetSDKManage;->a"
        r"\(\)Lcom/neutral/netsdk/HCNetSDK;\s+"
        r".*?"
        r"invoke-virtual \{v1, v13\}, "
        r"Lcom/neutral/netsdk/HCNetSDK;->NET_DVR_Logout_V30\(I\)Z\s+"
        r".*?"
        r'const-string v2, "\[dvr-config-sidecar\] done"\s+'
        r".*?"
        r"const/4 v0, 0x1\s+"
        r"invoke-static \{v0\}, Ljava/lang/System;->exit\(I\)V\s+"
        r"return-void\s+"
        r":neutral_get_ok\s+"
        r"sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;\s+"
        r'const-string v2, "\[dvr-config-sidecar\] outDump=disabled"',
        source,
        re.DOTALL,
    )

    assert match is not None


def test_dvr_config_smali_exits_on_jna_get_failure_before_dump() -> None:
    source = _read_dvr_config_smali_source()

    match = re.search(
        r"invoke-interface \{v7\}, "
        r"Lcom/videogo/hcnetsdk/jna/HCNetSDKByJNA;"
        r"->NET_DVR_GetLastError\(\)I\s+"
        r".*?"
        r"invoke-virtual \{v0, v1\}, "
        r"Ljava/io/PrintStream;->println\(Ljava/lang/String;\)V\s+"
        r"if-nez v14, :jna_get_ok\s+"
        r"invoke-static \{\}, "
        r"Lcom/videogo/add/hcnetsdk/jna/HCNetSDKJNAInstance;"
        r"->getInstance\(\)Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;\s+"
        r".*?"
        r"invoke-interface \{v1, v8\}, "
        r"Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;->NET_DVR_Logout\(I\)Z\s+"
        r".*?"
        r'const-string v2, "\[dvr-config-sidecar\] done"\s+'
        r".*?"
        r"const/4 v0, 0x1\s+"
        r"invoke-static \{v0\}, Ljava/lang/System;->exit\(I\)V\s+"
        r"return-void\s+"
        r":jna_get_ok\s+"
        r"if-nez v3, :do_dump",
        source,
        re.DOTALL,
    )

    assert match is not None
