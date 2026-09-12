/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.extension.aaa.jdbc.binding.cli;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Regression coverage for file-backed CLI passwords. */
public class CliPasswordFileTest {
    public static void main(String[] args) throws Exception {
        Path passwordFile = Files.createTempFile("aaa-jdbc-password-", ".txt");
        try {
            Files.write(passwordFile, "not-an-encryptor\nconfiguration\n".getBytes(StandardCharsets.UTF_8));

            String password = Cli.readPasswordFile(passwordFile.toString());
            if (!"not-an-encryptorconfiguration".equals(password)) {
                throw new AssertionError("Unexpected password-file contents: " + password);
            }
        } finally {
            Files.deleteIfExists(passwordFile);
        }
    }
}
