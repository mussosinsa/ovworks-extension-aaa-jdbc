/*
 * Copyright oVirt Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.extension.aaa.jdbc.core;

import org.ovirt.engine.api.extensions.aaa.Authn;

/**
 * Which refusals during a password change count towards locking the account.
 *
 * <p>An expired password is the state the change form exists to end, so reaching that form is not
 * a failed login. It used to be counted as one, which locked an account after five tries at the
 * form - and the administrator engine-setup creates starts with an expired password and has nobody
 * to unlock it.</p>
 */
public class CredentialsChangeFailureTest {
    public static void main(String[] args) {
        // the one refusal a change does not count
        expect(Authentication.isExpiredDuringCredChange(true, Authn.AuthResult.CREDENTIALS_EXPIRED),
                "an expired password during a change is not a failed attempt");

        // a wrong current password is a guess at the password, on a change as anywhere else
        expect(!Authentication.isExpiredDuringCredChange(true, Authn.AuthResult.CREDENTIALS_INCORRECT),
                "a wrong current password during a change is counted");
        expect(!Authentication.isExpiredDuringCredChange(true, Authn.AuthResult.ACCOUNT_LOCKED),
                "a locked account during a change is counted");
        expect(!Authentication.isExpiredDuringCredChange(true, Authn.AuthResult.GENERAL_ERROR),
                "any other refusal during a change is counted");

        // logging in is unchanged: an expired password there is still a failed login
        expect(!Authentication.isExpiredDuringCredChange(false, Authn.AuthResult.CREDENTIALS_EXPIRED),
                "an expired password during a login is still counted");
        expect(!Authentication.isExpiredDuringCredChange(false, Authn.AuthResult.CREDENTIALS_INCORRECT),
                "a wrong password during a login is still counted");
    }

    private static void expect(boolean result, String description) {
        if (!result) {
            throw new AssertionError("Credential change failure accounting: " + description);
        }
    }
}
