/*
 * Copyright 2014-2015 Red Hat Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
package org.ovirt.engine.extension.aaa.jdbc.binding.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.Charset;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.sql.DataSource;

import org.ovirt.engine.api.extensions.Base;
import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.extension.aaa.jdbc.Formatter;
import org.ovirt.engine.extension.aaa.jdbc.binding.Config;
import org.ovirt.engine.extension.aaa.jdbc.core.datasource.Sql;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;
import java.security.SecureRandom;

public class ExtensionUtils {

    private static final int IV_SIZE = 16; // AES 블록 크기
    private static final int KEY_SIZE = 32; // AES-256 키 크기


    public static final ExtMap JDBC_INFO;

    static {
        JDBC_INFO = new ExtMap().mput(
            Base.ContextKeys.AUTHOR,
            "The oVirt Project"
        ).mput(
            Base.ContextKeys.LICENSE,
            "ASL 2.0"
        ).mput(
            Base.ContextKeys.HOME_URL,
            "http://www.ovirt.org"
        ).mput(
            Base.ContextKeys.VERSION,
            Config.PACKAGE_VERSION
        ).mput(
            Base.ContextKeys.EXTENSION_NOTES,
            MessageFormat.format(
                "Display name: {0}",
                Config.PACKAGE_NAME
            )
        ).mput(
            Base.ContextKeys.BUILD_INTERFACE_VERSION,
            Base.INTERFACE_VERSION_CURRENT
        );
    }

    public static Properties loadIncludedConfiguration(ExtMap context) throws IOException {

        // ===== 1) /etc/ovirt-engine/encryptor/config.json 로드 =====
        String encryptFlag;
        int iterations = 200_000; // 기본값
        byte[] salt, nonce, keyCiphertext;

        try {
            File configFile = new File("/etc/ovirt-engine/encryptor/config.json");
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode cfg = objectMapper.readTree(configFile);

            encryptFlag = cfg.get("encrypt_flag").asText("").trim().toUpperCase();

            String saltB64  = optText(cfg, "salt");
            String nonceB64 = optText(cfg, "nonce");
            String ctB64    = optText(cfg, "decrypt_key_ciphertext");
            if (saltB64 == null || nonceB64 == null || ctB64 == null) {
                throw new IllegalStateException("config.json에 salt/nonce/decrypt_key_ciphertext가 없습니다.");
            }
            salt          = Base64.getDecoder().decode(saltB64);
            nonce         = Base64.getDecoder().decode(nonceB64);
            keyCiphertext = Base64.getDecoder().decode(ctB64);
            if (cfg.hasNonNull("iterations")) {
                iterations = cfg.get("iterations").asInt(200_000);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to read configuration from /etc/ovirt-engine/encryptor/config.json", e);
        }

        // ===== 2) 기존 구성 불러오고, baseDir 계산 =====
        try {
            Properties originalConfig = context.get(Base.ContextKeys.CONFIGURATION, Properties.class);
            Properties expandedConfig = new Properties(originalConfig);

            String baseDir = "/";
            try {
                baseDir = new File(context.get(Base.ContextKeys.CONFIGURATION_FILE, String.class, "/dummy")).getParent();
            } catch (Exception ex) {
                // ignore
            }

            // 대상 파일 키: config.datasource.file
            if (originalConfig.containsKey("config.datasource.file")) {
                File target = getRelativeFile(baseDir, originalConfig.getProperty("config.datasource.file"));

                if ("YES".equals(encryptFlag)) {
                    // ===== 3) MAC(또는 ENV) → PBKDF2(KEK) → AES-GCM(데이터키) → 파일 AES-CBC 복호화 =====
                    byte[] passphrase = getMacPassphrase(null); // null: 기본 라우트/NIC 자동
                    if (passphrase == null || passphrase.length == 0) {
                        String env = System.getenv("OVIRT_ENC_PASSPHRASE");
                        if (env == null || env.isEmpty()) {
                            throw new IllegalStateException("MAC 패스프레이즈 획득 실패 및 OVIRT_ENC_PASSPHRASE 미설정");
                        }
                        passphrase = env.getBytes(StandardCharsets.UTF_8);
                    }

                    // (선택) 호스트 바인딩 강화: /etc/machine-id pepper 추가
                    // try {
                    //     String machineId = Files.readString(Path.of("/etc/machine-id")).trim();
                    //     passphrase = concat(passphrase, ("|" + machineId).getBytes(StandardCharsets.UTF_8));
                    // } catch (Exception ignore) {}

                    byte[] kek = deriveKek(passphrase, salt, iterations, 32);
                    byte[] dataKey = decryptGCM(keyCiphertext, kek, nonce);
                    if (dataKey.length != 32) {
                        throw new IllegalStateException("복원된 데이터키 길이가 32바이트(AES-256)가 아닙니다.");
                    }

                    String decryptedContent = decryptFileCBC(target, dataKey); // IV=파일 선두 16바이트
                    expandedConfig.load(
                        new InputStreamReader(
                            new ByteArrayInputStream(decryptedContent.getBytes(StandardCharsets.UTF_8)),
                            StandardCharsets.UTF_8
                        )
                    );
                } else {
                    // 평문 로드
                    expandedConfig.load(
                        new InputStreamReader(new FileInputStream(target), StandardCharsets.UTF_8)
                    );
                }
            }
            return expandedConfig;
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }


    private static File getRelativeFile(String baseDir, String fileName) {
        File f = new File(fileName);
        if (!f.isAbsolute()) {
            f = new File(baseDir, fileName);
        }
        return f;
    }

    private static String decryptFileWithOpenSSL(File file, String keyHex){

      final int IV_SIZE = 16; // AES block size

      byte[] key = hexStringToByteArray(keyHex);

      try (FileInputStream fis = new FileInputStream(file)) {


        // Read IV
        byte[] iv = new byte[IV_SIZE];
        fis.read(iv);

        // Read the encrypted data
        byte[] encryptedData = fis.readAllBytes();
        fis.close();

        // Create AES key and IV parameter spec
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Initialize Cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Decrypt and remove padding
        byte[] decryptedData = cipher.doFinal(encryptedData);

        return new String(decryptedData, StandardCharsets.UTF_8);
      } catch (Exception e) {
         throw new RuntimeException("Error during AES decryption of file: ", e);
      }


   }

   // Utility to convert a hex string to a byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static Path getDbScriptsDir(String configurationFile) {
        // config file is located in ${PREFIX}/etc/ovirt-engine/extension.d/${NAME}.properties (for API calls) or
        // in ${PREFIX}/etc/ovirt-engine/aaa/${NAME}.properties (for CLI calls)
        Path prefixDir = Paths.get(configurationFile).normalize().getParent().getParent().getParent().getParent();
        if (prefixDir.getNameCount() == 0) {
            // RPM installation, ${PREFIX} should be /usr instead of /
            prefixDir = Paths.get("/usr");
        }
        // dbscripts are located in ${PREFIX}/share/ovirt-engine-extension-aaa-jdbc/dbscripts/upgrade
        return Paths.get(prefixDir.toString(), "share/ovirt-engine-extension-aaa-jdbc/dbscripts/upgrade");

    }

    private static String getLatestUpgradeScriptName(Path upgradeScriptsDir) throws IOException {
        List<String> fileNames = new ArrayList<>();
        DirectoryStream.Filter<Path> fileFilter = new DirectoryStream.Filter<Path>() {
            public boolean accept(Path file) throws IOException {
                return !Files.isDirectory(file);
            }
        };
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(upgradeScriptsDir, fileFilter)) {
            for (Path path : directoryStream) {
                // in schema_version table script name contains "upgrade/" prefix
                fileNames.add(path.subpath(path.getNameCount() - 2, path.getNameCount()).toString());
            }
        } finally {
        }
        Collections.sort(fileNames);
        return fileNames.get(fileNames.size() -1);
    }

    public static void checkDbVersion(DataSource ds, String configurationFile)
    throws IOException, SQLException {
        try (Connection conn = ds.getConnection()) {
            boolean uptodate = new Sql.Query(
                Formatter.format(
                    "SELECT COUNT(script) AS count FROM schema_version WHERE script = {}",
                    Formatter.escapeString(
                        getLatestUpgradeScriptName(
                            getDbScriptsDir(configurationFile)
                        )
                    )
                )
            ).asInteger(conn, "count") == 1;
            if (!uptodate) {
                throw new RuntimeException(
                    "Database schema is older than required by currently installed ovirt-engine-extension-aaa-jdbc " +
                    "package version. Please upgrade profile database schema before proceeding (for more info about " +
                    "upgrade please take a look at README.admin file contained in ovirt-engine-extension-aaa-jdbc " +
                    "package)."
                );
            }
        }
    }
    
 // JSON 필드 안전 추출
    private static String optText(JsonNode node, String field) {
        return (node.hasNonNull(field) ? node.get(field).asText() : null);
    }

    // AES-256-CBC 복호화 (IV=파일 앞 16바이트, PKCS5Padding)
    private static String decryptFileCBC(File file, byte[] dataKey) {
        final int IV_SIZE = 16;
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] iv = new byte[IV_SIZE];
            int n = fis.read(iv);
            if (n != IV_SIZE) throw new IllegalStateException("IV 읽기 실패 또는 파일 손상: " + file);

            byte[] enc = fis.readAllBytes();

            SecretKeySpec keySpec = new SecretKeySpec(dataKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            byte[] plain = cipher.doFinal(enc);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("AES-256-CBC 파일 복호화 오류: " + file, e);
        }
    }

    // AES-GCM(KEK)로 데이터키 복호화
    private static byte[] decryptGCM(byte[] ciphertext, byte[] kek, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), spec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM 복호화 실패(데이터키)", e);
        }
    }

    // PBKDF2-HMAC-SHA256 (KEK 도출)
    private static byte[] deriveKek(byte[] passphrase, byte[] salt, int iterations, int outLen) {
        try {
            PBEKeySpec spec = new PBEKeySpec(
                new String(passphrase, StandardCharsets.UTF_8).toCharArray(),
                salt,
                iterations,
                outLen * 8
            );
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 KEK 도출 실패", e);
        }
    }

    // MAC 패스프레이즈 획득(기본 라우트 우선, 폴백은 활성 NIC)
    private static byte[] getMacPassphrase(String preferIface) {
        try {
            if (preferIface != null && !preferIface.isEmpty()) {
                String mac = readMacByName(preferIface);
                if (mac != null) return mac.getBytes(StandardCharsets.US_ASCII);
            }
            String def = detectDefaultIface();
            if (def != null) {
                String mac = readMacByName(def);
                if (mac != null) return mac.getBytes(StandardCharsets.US_ASCII);
            }
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (ni == null || ni.isLoopback() || ni.isVirtual() || !ni.isUp()) continue;
                byte[] hw = ni.getHardwareAddress();
                if (hw != null && hw.length == 6) {
                    return toMacString(hw).getBytes(StandardCharsets.US_ASCII);
                }
            }
        } catch (Exception ignore) {}
        return null;
    }

    private static String readMacByName(String iface) {
        try {
            NetworkInterface ni = NetworkInterface.getByName(iface);
            if (ni == null || !ni.isUp()) return null;
            byte[] hw = ni.getHardwareAddress();
            if (hw == null || hw.length != 6) return null;
            return toMacString(hw);
        } catch (Exception e) {
            return null;
        }
    }

    private static String toMacString(byte[] hw) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hw.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", hw[i]));
        }
        return sb.toString();
    }

    // 기본 라우트 NIC 감지(/proc/net/route)
    private static String detectDefaultIface() {
        File f = new File("/proc/net/route");
        if (!f.exists()) return null;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            br.readLine(); // header skip
            List<String[]> zeros = new ArrayList<>();
            String line;
            while ((line = br.readLine()) != null) {
                String[] c = line.trim().split("\\s+");
                if (c.length < 11) continue;
                String iface = c[0];
                String dest  = c[1];
                String flags = c[3];
                if (!"00000000".equals(dest)) continue;
                zeros.add(c);
                try {
                    int fl = Integer.parseInt(flags, 16);
                    if ((fl & 0x2) != 0) return iface; // 게이트웨이 플래그 우선
                } catch (Exception ignore) {}
            }
            if (!zeros.isEmpty()) return zeros.get(0)[0];
        } catch (Exception ignore) {}
        return null;
    }

    // (pepper 추가 시 사용)
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

}
