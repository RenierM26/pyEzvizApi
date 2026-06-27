import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.videogo.add.device.HCNETUtil;

public final class DvrConfigProbe {
    private DvrConfigProbe() {}

    private static int parseInt(String value, String name) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exc) {
            throw new IllegalArgumentException(name + " must be an integer: " + value, exc);
        }
    }

    private static String hex(byte[] value, int length) {
        StringBuilder out = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            int b = value[i] & 0xff;
            if (b < 16) {
                out.append('0');
            }
            out.append(Integer.toHexString(b));
        }
        return out.toString();
    }

    public static void main(String[] args) {
        System.out.println("[dvr-config-sidecar] start");
        if (args.length < 7) {
            System.out.println(
                "[dvr-config-sidecar] usage: <ip> <port> <user> <password> <command> <channel> <outSize>"
            );
            System.exit(2);
            return;
        }

        String ip = args[0];
        int port = parseInt(args[1], "port");
        String user = args[2];
        String password = args[3];
        int command = parseInt(args[4], "command");
        int channel = parseInt(args[5], "channel");
        int outSize = parseInt(args[6], "outSize");
        boolean dumpOutput = args.length < 8 || !"no-dump".equals(args[7]);

        if (command == 1006) {
            com.neutral.netsdk.NET_DVR_DEVICEINFO_V30 neutralDeviceInfo =
                new com.neutral.netsdk.NET_DVR_DEVICEINFO_V30();
            int neutralLoginId = com.videogo.add.device.HCNETUtil.r(
                ip,
                port,
                user,
                password,
                neutralDeviceInfo
            );
            System.out.println("[dvr-config-sidecar] loginId=" + neutralLoginId);
            boolean ok = false;
            if (neutralLoginId >= 0) {
                com.neutral.netsdk.NET_DVR_USER_V30 userConfig =
                    new com.neutral.netsdk.NET_DVR_USER_V30();
                ok = com.videogo.hcnetsdk.HCNetSDKManage.a().NET_DVR_GetDVRConfig(
                    neutralLoginId,
                    command,
                    channel,
                    userConfig
                );
            }
            int lastError = com.videogo.hcnetsdk.HCNetSDKManage.a().NET_DVR_GetLastError();
            System.out.println(
                "[dvr-config-sidecar] get ret=" + ok
                    + " command=" + command
                    + " channel=" + channel
                    + " object=NET_DVR_USER_V30"
                    + " lastError=" + lastError
            );
            System.out.println("[dvr-config-sidecar] outDump=disabled");
            if (neutralLoginId >= 0) {
                boolean neutralLogout = com.videogo.hcnetsdk.HCNetSDKManage.a().NET_DVR_Logout_V30(neutralLoginId);
                System.out.println("[dvr-config-sidecar] logout=" + neutralLogout);
            }
            System.out.println("[dvr-config-sidecar] done");
            return;
        }

        com.videogo.add.hcnetsdk.jna.HCNetSDKByJNA.NET_DVR_DEVICEINFO_V40 deviceInfo =
            new com.videogo.add.hcnetsdk.jna.HCNetSDKByJNA.NET_DVR_DEVICEINFO_V40();
        int loginId = HCNETUtil.s(ip, port, user, password, deviceInfo);
        System.out.println("[dvr-config-sidecar] loginId=" + loginId);
        if (loginId < 0) {
            System.exit(1);
            return;
        }

        try {
            Memory out = new Memory(outSize);
            out.clear(outSize);
            if (outSize >= 4) {
                out.setInt(0, outSize);
            }
            IntByReference bytesReturned = new IntByReference();
            Pointer pointer = out;
            boolean ok = com.videogo.hcnetsdk.jna.HCNetSDKJNAInstance.getInstance().NET_DVR_GetDVRConfig(
                loginId,
                command,
                channel,
                pointer,
                outSize,
                bytesReturned
            );
            int returned = bytesReturned.getValue();
            int lastError = com.videogo.hcnetsdk.jna.HCNetSDKJNAInstance.getInstance().NET_DVR_GetLastError();
            System.out.println(
                "[dvr-config-sidecar] get ret=" + ok
                    + " command=" + command
                    + " channel=" + channel
                    + " outSize=" + outSize
                    + " bytesReturned=" + returned
                    + " lastError=" + lastError
            );
            if (dumpOutput) {
                int dumpLength = Math.max(0, Math.min(outSize, returned > 0 ? returned : outSize));
                byte[] bytes = out.getByteArray(0, dumpLength);
                System.out.println("[dvr-config-sidecar] outHex=" + hex(bytes, bytes.length));
            } else {
                System.out.println("[dvr-config-sidecar] outDump=disabled");
            }
        } finally {
            boolean logout = com.videogo.add.hcnetsdk.jna.HCNetSDKJNAInstance.getInstance().NET_DVR_Logout(loginId);
            System.out.println("[dvr-config-sidecar] logout=" + logout);
            System.out.println("[dvr-config-sidecar] done");
        }
    }
}
