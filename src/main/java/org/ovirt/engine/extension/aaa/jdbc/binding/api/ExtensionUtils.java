/*
 * Copyright 2014-2015 Red Hat Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ovirt.engine.extension.aaa.jdbc.binding.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.sql.Connection;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;

import org.ovirt.engine.api.extensions.Base;
import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.extension.aaa.jdbc.Formatter;
import org.ovirt.engine.extension.aaa.jdbc.binding.Config;
import org.ovirt.engine.extension.aaa.jdbc.core.datasource.Sql;

public class ExtensionUtils {

    private static final byte[] ENCRYPTED_MAGIC = "OVENC001".getBytes(StandardCharsets.US_ASCII);
    private static final int ENCRYPTED_VERSION = 1;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int DATA_KEY_SIZE = 32;
    private static final int WRAPPED_KEY_SIZE = DATA_KEY_SIZE + 16;
    private static final int HEADER_SIZE = 8 + 1 + 4 + 16 + 12 + 12 + 2;
    private static final Path ENCRYPTOR_CONFIG = Paths.get("/etc/ovirt-engine/encryptor/config.json");
    private static final String DEFAULT_CREDENTIAL = "ovirt-encryptor-passphrase";
    private static final String PASSPHRASE_ENV = "OVIRT_ENCRYPTOR_PASSPHRASE";

    public static final ExtMap JDBC_INFO = new ExtMap().mput(
        Base.ContextKeys.AUTHOR, "The oVirt Project"
    ).mput(
        Base.ContextKeys.LICENSE, "ASL 2.0"
    ).mput(
        Base.ContextKeys.HOME_URL, "http://www.ovirt.org"
    ).mput(
        Base.ContextKeys.VERSION, Config.PACKAGE_VERSION
    ).mput(
        Base.ContextKeys.EXTENSION_NOTES,
        MessageFormat.format("Display name: {0}", Config.PACKAGE_NAME)
    ).mput(
        Base.ContextKeys.BUILD_INTERFACE_VERSION, Base.INTERFACE_VERSION_CURRENT
    );

    /** Load a properties file, transparently decrypting the OVENC001 format. */
    public static Properties loadPropertiesFromFile(String filename) throws IOException {
        return loadPropertiesFromFile(Paths.get(filename), ENCRYPTOR_CONFIG);
    }

    static Properties loadPropertiesFromFile(Path filename, Path encryptorConfig) throws IOException {
        byte[] content = readRegularFile(filename, false);
        if (startsWithMagic(content)) {
            JsonNode config = loadEncryptorConfig(encryptorConfig);
            byte[] passphrase = obtainPassphrase(config);
            try {
                content = decryptOvenc001(content, passphrase);
            } finally {
                Arrays.fill(passphrase, (byte) 0);
            }
        }

        Properties properties = new Properties();
        try (InputStreamReader reader = new InputStreamReader(
                new ByteArrayInputStream(content), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    public static Properties loadIncludedConfiguration(ExtMap context) throws IOException {
        Properties original = context.get(Base.ContextKeys.CONFIGURATION, Properties.class);
        Properties expanded = new Properties(original);
        String included = original.getProperty("config.datasource.file");
        if (included != null) {
            String configurationFile = context.get(
                Base.ContextKeys.CONFIGURATION_FILE, String.class, "/dummy"
            );
            File target = getRelativeFile(new File(configurationFile).getParent(), included);
            expanded.putAll(loadPropertiesFromFile(target.getPath()));
        }
        return expanded;
    }

    private static File getRelativeFile(String baseDir, String fileName) {
        File file = new File(fileName);
        return file.isAbsolute() ? file : new File(baseDir, fileName);
    }

    private static boolean startsWithMagic(byte[] data) {
        if (data.length < ENCRYPTED_MAGIC.length) {
            return false;
        }
        for (int i = 0; i < ENCRYPTED_MAGIC.length; i++) {
            if (data[i] != ENCRYPTED_MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    static byte[] decryptOvenc001(byte[] data, byte[] passphrase) throws IOException {
        if (data.length < HEADER_SIZE + WRAPPED_KEY_SIZE + 16) {
            throw new IOException("Encrypted file is truncated");
        }

        ByteBuffer header = ByteBuffer.wrap(data, 0, HEADER_SIZE).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[ENCRYPTED_MAGIC.length];
        header.get(magic);
        int version = Byte.toUnsignedInt(header.get());
        int iterations = header.getInt();
        byte[] salt = new byte[16];
        byte[] keyNonce = new byte[12];
        byte[] dataNonce = new byte[12];
        header.get(salt);
        header.get(keyNonce);
        header.get(dataNonce);
        int wrappedSize = Short.toUnsignedInt(header.getShort());

        if (!Arrays.equals(magic, ENCRYPTED_MAGIC)) {
            throw new IOException("Encrypted file magic header is missing");
        }
        if (version != ENCRYPTED_VERSION) {
            throw new IOException("Unsupported encrypted file version: " + version);
        }
        if (iterations != PBKDF2_ITERATIONS) {
            throw new IOException("Invalid PBKDF2 iteration count for this format version");
        }
        if (wrappedSize != WRAPPED_KEY_SIZE || data.length < HEADER_SIZE + wrappedSize + 16) {
            throw new IOException("Invalid wrapped data-key length");
        }

        byte[] fixedHeader = Arrays.copyOfRange(data, 0, HEADER_SIZE);
        byte[] wrappedKey = Arrays.copyOfRange(data, HEADER_SIZE, HEADER_SIZE + wrappedSize);
        byte[] ciphertext = Arrays.copyOfRange(data, HEADER_SIZE + wrappedSize, data.length);
        byte[] kek = null;
        byte[] dataKey = null;
        try {
            kek = deriveKey(passphrase, salt, iterations);
            dataKey = decryptGcm(wrappedKey, kek, keyNonce, fixedHeader);
            if (dataKey.length != DATA_KEY_SIZE) {
                throw new IOException("Invalid unwrapped data-key length");
            }
            byte[] associatedData = new byte[fixedHeader.length + wrappedKey.length];
            System.arraycopy(fixedHeader, 0, associatedData, 0, fixedHeader.length);
            System.arraycopy(wrappedKey, 0, associatedData, fixedHeader.length, wrappedKey.length);
            return decryptGcm(ciphertext, dataKey, dataNonce, associatedData);
        } catch (AEADBadTagException e) {
            throw new IOException(
                "Authentication failed: file is damaged, modified, or the key is wrong", e
            );
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Unable to decrypt encrypted configuration", e);
        } finally {
            if (kek != null) {
                Arrays.fill(kek, (byte) 0);
            }
            if (dataKey != null) {
                Arrays.fill(dataKey, (byte) 0);
            }
        }
    }

    private static byte[] deriveKey(byte[] passphrase, byte[] salt, int iterations) throws Exception {
        char[] characters = new String(passphrase, StandardCharsets.UTF_8).toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(characters, salt, iterations, 256);
            try {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    private static byte[] decryptGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    private static JsonNode loadEncryptorConfig(Path path) throws IOException {
        byte[] data = readRegularFile(path, true);
        JsonNode config = new ObjectMapper().readTree(data);
        if (config == null || !config.isObject()) {
            throw new IOException("Encryptor configuration must be a JSON object");
        }
        return config;
    }

    private static byte[] obtainPassphrase(JsonNode config) throws IOException {
        String credentialDirectory = System.getenv("CREDENTIALS_DIRECTORY");
        String credentialName = text(config, "systemd_credential", DEFAULT_CREDENTIAL);
        if (credentialDirectory != null) {
            Path credential = Paths.get(credentialDirectory, credentialName);
            if (Files.exists(credential, LinkOption.NOFOLLOW_LINKS)) {
                return trimNewlines(readSecretFile(credential));
            }
        }

        String environmentSecret = System.getenv(PASSPHRASE_ENV);
        if (environmentSecret != null && !environmentSecret.isEmpty()) {
            return environmentSecret.getBytes(StandardCharsets.UTF_8);
        }

        String secretFile = text(config, "secret_file", null);
        if (secretFile != null) {
            return trimNewlines(readSecretFile(Paths.get(secretFile)));
        }
        throw new IOException(
            "No key credential available (systemd credential, environment, or 0600 secret file)"
        );
    }

    private static byte[] readSecretFile(Path path) throws IOException {
        byte[] secret = readRegularFile(path, true);
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                throw new IOException("Passphrase file permissions must be 0600 or stricter: " + path);
            }
        } catch (UnsupportedOperationException e) {
            // POSIX permissions are unavailable on this filesystem.
        }
        if (secret.length == 0) {
            throw new IOException("Passphrase file is empty: " + path);
        }
        return secret;
    }

    private static byte[] readRegularFile(Path path, boolean rejectWritable) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Refusing non-regular or symbolic-link file: " + path);
        }
        if (rejectWritable) {
            try {
                Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
                if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    throw new IOException("Refusing group/other-writable file: " + path);
                }
            } catch (UnsupportedOperationException e) {
                // POSIX permissions are unavailable on this filesystem.
            }
        }
        return Files.readAllBytes(path);
    }

    private static byte[] trimNewlines(byte[] value) throws IOException {
        int end = value.length;
        while (end > 0 && (value[end - 1] == '\r' || value[end - 1] == '\n')) {
            end--;
        }
        if (end == 0) {
            throw new IOException("Passphrase file is empty");
        }
        return Arrays.copyOf(value, end);
    }

    private static String text(JsonNode node, String name, String defaultValue) {
        JsonNode value = node.get(name);
        return value == null || value.isNull() ? defaultValue : value.asText();
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

}
