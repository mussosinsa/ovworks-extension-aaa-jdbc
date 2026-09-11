/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.extension.aaa.jdbc.core;

public class SchemaTest {
    public static void main(String[] args) {
        long now = 1_000_000L;
        if (!Schema.isManualUnlock(now, now) || !Schema.isManualUnlock(now - 1, now)) {
            throw new AssertionError("current or past unlock time must clear failed login history");
        }
        if (Schema.isManualUnlock(now + 1, now)) {
            throw new AssertionError("future automatic lock must preserve failed login history");
        }
    }
}
