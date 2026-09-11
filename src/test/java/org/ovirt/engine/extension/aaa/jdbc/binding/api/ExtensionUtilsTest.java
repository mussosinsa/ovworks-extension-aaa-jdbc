/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.extension.aaa.jdbc.binding.api;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ExtensionUtilsTest {
    private static final byte[] MAGIC = "OVVLT001".getBytes(StandardCharsets.US_ASCII);
    private static final int HEADER_SIZE = 8 + 1 + 12 + 2;

    public static void main(String[] args) throws Exception {
        byte[] plaintext = "vault protected passphrase".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(nonce);
        byte[] envelope = envelope(plaintext, key, nonce, "vault:v1:test");

        byte[] actual = ExtensionUtils.decryptOvvlt001(envelope, ignored -> key.clone());
        if (!Arrays.equals(plaintext, actual)) {
            throw new AssertionError("OVVLT001 plaintext mismatch");
        }

        envelope[envelope.length - 1] ^= 1;
        try {
            ExtensionUtils.decryptOvvlt001(envelope, ignored -> key.clone());
            throw new AssertionError("tampered OVVLT001 envelope was accepted");
        } catch (java.io.IOException expected) {
            // Authentication failures must fail closed.
        }
    }

    private static byte[] envelope(byte[] plaintext, byte[] key, byte[] nonce, String wrapped)
            throws Exception {
        byte[] wrappedBytes = wrapped.getBytes(StandardCharsets.UTF_8);
        byte[] header = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC).put((byte) 1).put(nonce).putShort((short) wrappedBytes.length).array();
        byte[] aad = ByteBuffer.allocate(header.length + wrappedBytes.length)
            .put(header).put(wrappedBytes).array();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);
        return ByteBuffer.allocate(aad.length + ciphertext.length).put(aad).put(ciphertext).array();
    }
}
