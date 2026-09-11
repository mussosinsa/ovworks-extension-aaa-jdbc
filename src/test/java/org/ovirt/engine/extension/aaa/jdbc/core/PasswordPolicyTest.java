/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.extension.aaa.jdbc.core;

public class PasswordPolicyTest {
    public static void main(String[] args) {
        expect(Authentication.containsKeyboardSequence("Safe-qwer-9!"), "qwer");
        expect(Authentication.containsKeyboardSequence("Safe-AsDf-9!"), "mixed-case asdf");
        expect(Authentication.containsKeyboardSequence("Safe-1234-A!"), "1234");
        expect(Authentication.containsKeyboardSequence("Safe-4321-A!"), "4321");
        expect(!Authentication.containsKeyboardSequence("Safe-1357-A!"), "non-sequential keys");

        expect(Authentication.containsSequentialCharacters("Safe-abcd-9!"), "abcd");
        expect(Authentication.containsSequentialCharacters("Safe-DCBA-9!"), "DCBA");
        expect(!Authentication.containsSequentialCharacters("Safe-/012-A!"), "mixed punctuation/digits");

        expect(Authentication.containsRepeatedPattern("Safe-aaa-9!"), "repeated letters");
        expect(Authentication.containsRepeatedPattern("Safe-111-A!"), "repeated digits");
        expect(!Authentication.containsRepeatedPattern("Safe-$$$-A1"), "repeated special characters");
        expect(!Authentication.containsRepeatedPattern("Safe-abab-1!"), "non-contiguous repeated pattern");

        expect(Authentication.containsSpecialCharacter("SecurePassword1!"), "special character");
        expect(!Authentication.containsSpecialCharacter("SecurePassword12"), "missing special character");
    }

    private static void expect(boolean result, String description) {
        if (!result) {
            throw new AssertionError("Password policy check failed: " + description);
        }
    }
}
