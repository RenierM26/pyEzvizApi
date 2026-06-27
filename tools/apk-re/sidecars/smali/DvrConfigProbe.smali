.class public final LDvrConfigProbe;
.super Ljava/lang/Object;


# direct methods
.method private constructor <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static main([Ljava/lang/String;)V
    .registers 16

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v1, "[dvr-config-sidecar] start"

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    array-length v0, p0

    const/4 v1, 0x7

    if-ge v0, v1, :args_ok

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v1, "[dvr-config-sidecar] usage: <ip> <port> <user> <password> <command> <channel> <outSize>"

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    const/4 v0, 0x2

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void

    :args_ok
    const/4 v0, 0x0

    aget-object v2, p0, v0

    const/4 v0, 0x1

    aget-object v0, p0, v0

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v3

    const/4 v0, 0x2

    aget-object v4, p0, v0

    const/4 v0, 0x3

    aget-object v5, p0, v0

    const/4 v0, 0x4

    aget-object v0, p0, v0

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v9

    const/4 v0, 0x5

    aget-object v0, p0, v0

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v10

    const/4 v0, 0x6

    aget-object v0, p0, v0

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v12

    const/16 v0, 0x3ee

    if-ne v9, v0, :jna_login_config

    new-instance v11, Lcom/neutral/netsdk/NET_DVR_DEVICEINFO_V30;

    invoke-direct {v11}, Lcom/neutral/netsdk/NET_DVR_DEVICEINFO_V30;-><init>()V

    invoke-static {v2, v3, v4, v5, v11}, Lcom/videogo/add/device/HCNETUtil;->r(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Lcom/neutral/netsdk/NET_DVR_DEVICEINFO_V30;)I

    move-result v13

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v6, "[dvr-config-sidecar] loginId="

    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    if-gez v13, :neutral_login_ok

    const/4 v0, 0x1

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void

    :neutral_login_ok
    const/4 v14, 0x0

    new-instance v0, Lcom/neutral/netsdk/NET_DVR_USER_V30;

    invoke-direct {v0}, Lcom/neutral/netsdk/NET_DVR_USER_V30;-><init>()V

    invoke-static {}, Lcom/videogo/hcnetsdk/HCNetSDKManage;->a()Lcom/neutral/netsdk/HCNetSDK;

    move-result-object v1

    invoke-virtual {v1, v13, v9, v10, v0}, Lcom/neutral/netsdk/HCNetSDK;->NET_DVR_GetDVRConfig(IIILcom/neutral/netsdk/NET_DVR_CONFIG;)Z

    move-result v14

    invoke-static {}, Lcom/videogo/hcnetsdk/HCNetSDKManage;->a()Lcom/neutral/netsdk/HCNetSDK;

    move-result-object v1

    invoke-virtual {v1}, Lcom/neutral/netsdk/HCNetSDK;->NET_DVR_GetLastError()I

    move-result v6

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "[dvr-config-sidecar] get ret="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " command="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " channel="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " object=NET_DVR_USER_V30 lastError="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    if-nez v14, :neutral_get_ok

    invoke-static {}, Lcom/videogo/hcnetsdk/HCNetSDKManage;->a()Lcom/neutral/netsdk/HCNetSDK;

    move-result-object v1

    invoke-virtual {v1, v13}, Lcom/neutral/netsdk/HCNetSDK;->NET_DVR_Logout_V30(I)Z

    move-result v6

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "[dvr-config-sidecar] logout="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "[dvr-config-sidecar] done"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    const/4 v0, 0x1

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void

    :neutral_get_ok
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "[dvr-config-sidecar] outDump=disabled"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    invoke-static {}, Lcom/videogo/hcnetsdk/HCNetSDKManage;->a()Lcom/neutral/netsdk/HCNetSDK;

    move-result-object v1

    invoke-virtual {v1, v13}, Lcom/neutral/netsdk/HCNetSDK;->NET_DVR_Logout_V30(I)Z

    move-result v6

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "[dvr-config-sidecar] logout="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    goto :done

    :jna_login_config
    new-instance v6, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA$NET_DVR_DEVICEINFO_V40;

    invoke-direct {v6}, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA$NET_DVR_DEVICEINFO_V40;-><init>()V

    invoke-static {v2, v3, v4, v5, v6}, Lcom/videogo/add/device/HCNETUtil;->s(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA$NET_DVR_DEVICEINFO_V40;)I

    move-result v8

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "[dvr-config-sidecar] loginId="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    if-gez v8, :jna_login_ok

    const/4 v0, 0x1

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void

    :jna_login_ok

    const/4 v3, 0x1

    array-length v0, p0

    const/16 v1, 0x8

    if-lt v0, v1, :dump_flag_done

    const/4 v0, 0x7

    aget-object v0, p0, v0

    const-string v1, "no-dump"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :dump_flag_done

    const/4 v3, 0x0

    :dump_flag_done
    new-instance v11, Lcom/sun/jna/Memory;

    int-to-long v0, v12

    invoke-direct {v11, v0, v1}, Lcom/sun/jna/Memory;-><init>(J)V

    invoke-virtual {v11, v0, v1}, Lcom/sun/jna/Memory;->clear(J)V

    const/4 v0, 0x4

    if-lt v12, v0, :after_size_write

    const-wide/16 v0, 0x0

    invoke-virtual {v11, v0, v1, v12}, Lcom/sun/jna/Memory;->setInt(JI)V

    :after_size_write
    new-instance v13, Lcom/sun/jna/ptr/IntByReference;

    invoke-direct {v13}, Lcom/sun/jna/ptr/IntByReference;-><init>()V

    invoke-static {}, Lcom/videogo/hcnetsdk/jna/HCNetSDKJNAInstance;->getInstance()Lcom/videogo/hcnetsdk/jna/HCNetSDKByJNA;

    move-result-object v7

    invoke-interface/range {v7 .. v13}, Lcom/videogo/hcnetsdk/jna/HCNetSDKByJNA;->NET_DVR_GetDVRConfig(IIILcom/sun/jna/Pointer;ILcom/sun/jna/ptr/IntByReference;)Z

    move-result v14

    invoke-virtual {v13}, Lcom/sun/jna/ptr/IntByReference;->getValue()I

    move-result v15

    invoke-interface {v7}, Lcom/videogo/hcnetsdk/jna/HCNetSDKByJNA;->NET_DVR_GetLastError()I

    move-result v6

    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "[dvr-config-sidecar] get ret="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " command="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " channel="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " outSize="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " bytesReturned="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    const-string v2, " lastError="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    if-nez v14, :jna_get_ok

    invoke-static {}, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKJNAInstance;->getInstance()Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;

    move-result-object v1

    invoke-interface {v1, v8}, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;->NET_DVR_Logout(I)Z

    move-result v6

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "[dvr-config-sidecar] logout="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "[dvr-config-sidecar] done"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    const/4 v0, 0x1

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void

    :jna_get_ok
    if-nez v3, :do_dump

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "[dvr-config-sidecar] outDump=disabled"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    goto :after_dump

    :do_dump
    move v0, v15

    if-gtz v0, :dump_len_positive

    move v0, v12

    :dump_len_positive
    if-le v0, v12, :dump_len_not_too_large

    move v0, v12

    :dump_len_not_too_large
    if-gez v0, :dump_len_ok

    const/4 v0, 0x0

    :dump_len_ok
    const-wide/16 v2, 0x0

    invoke-virtual {v11, v2, v3, v0}, Lcom/sun/jna/Memory;->getByteArray(JI)[B

    move-result-object v1

    const/4 v2, 0x2

    invoke-static {v1, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    move-result-object v1

    sget-object v2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "[dvr-config-sidecar] outBase64="

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    :after_dump
    invoke-static {}, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKJNAInstance;->getInstance()Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;

    move-result-object v1

    invoke-interface {v1, v8}, Lcom/videogo/add/hcnetsdk/jna/HCNetSDKByJNA;->NET_DVR_Logout(I)Z

    move-result v6

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "[dvr-config-sidecar] logout="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    :done
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    const-string v2, "[dvr-config-sidecar] done"

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    return-void
.end method
