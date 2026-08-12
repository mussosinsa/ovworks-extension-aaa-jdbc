package org.ovirt.engine.extension.aaa.jdbc.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sql.DataSource;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.api.extensions.ExtMap;
import org.ovirt.engine.api.extensions.aaa.Authn;
import org.ovirt.engine.extension.aaa.jdbc.DateUtils;
import org.ovirt.engine.extension.aaa.jdbc.Global;
import org.ovirt.engine.extension.aaa.jdbc.core.datasource.Sql;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Authentication implements Observer {
    public static class AuthRecord {
        public final String principal; // M
        public final long validTo; // M

        public AuthRecord(String principal, long validTo) {
            this.principal = principal;
            this.validTo = validTo;
        }

        @Override
        public String toString() {
            return "AuthRecord{" +
                "principal='" + principal + '\'' +
                ", validTo=" + DateUtils.toISO(validTo) +
                '}';
        }
    }

    public static class AuthResponse {
        public final AuthRecord authRecord;
        public final String principal;
        public final int result; // Only result is mandatory
        public final String dailyMsg;
        public final String baseMsg;

        private final Schema.User user;

        private AuthResponse(
            AuthRecord authRecord,
            Schema.User user,
            int result,
            String dailyMsg,
            String baseMsg
        ) {
            this.authRecord = authRecord;
            this.user = user;
            this.principal = (user == null ? null : user.getName());
            this.result = result;
            this.dailyMsg = dailyMsg;
            this.baseMsg = baseMsg;
        }

        public static AuthResponse negative(int result, Schema.User user, String baseMsg){
            return new AuthResponse(null, user, result, null, baseMsg);
        }

        public static AuthResponse negative(int result){
            return new AuthResponse(null, null, result, null, null);
        }

        public static AuthResponse positive(AuthRecord authRecord, Schema.User user, String dailyMsg){
            return new AuthResponse(authRecord, user, Authn.AuthResult.SUCCESS, dailyMsg, null);
        }

        public static AuthResponse positive() {
            return new AuthResponse(null, null, Authn.AuthResult.SUCCESS, null, null);
        }

        @Override
        public String toString() {
            return "AuthResponse{" +
                "authRecord= " +
                ((authRecord != null)? authRecord.toString(): null) +
                ", principal='" + principal + '\'' +
                ", result=" + result +
                ", dailyMsg='" + dailyMsg + '\'' +
                ", baseMsg='" + baseMsg + '\'' +
                '}';
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(Authentication.class);
    public static final int MIN_SLEEP = 100;


    static final private Pattern COMPLEXITY_PATTERN = Pattern.compile(
        "(?<name>[^:]*)" +
        ":" +
        "(" +
            "(chars=(?<chars>.*?)::)|" +
            "(min=(?<min>.*?)::)" +
        ")*"
    );


    private final DataSource ds;
    private ExtMap settings;
    private Complexity complexity;
    public Authentication(DataSource ds) {
        this.ds = ds;
    }

    public AuthResponse doAuth(
        String subject,
        String credentials,
        boolean credChange,
        String newCredentials
    ) throws GeneralSecurityException, SQLException, IOException {
        long loginTime = System.currentTimeMillis(); // start the clock
        AuthResponse response = null;

        LOG.debug("Authenticating subject:{} login time:{}", subject, DateUtils.toISO(loginTime));
        try {
            response = authenticate(
                subject,
                credentials,
                loginTime
            );
            if (
                credChange &&
                (
                    response.result == Authn.AuthResult.SUCCESS ||
                    (
                        response.result == Authn.AuthResult.CREDENTIALS_EXPIRED &&
                        settings.get(Schema.Settings.ALLOW_EXPIRED_PASSWORD_CHANGE, Boolean.class)
                    )
                )
            ) {
                AuthResponse credChangeResponse = checkCredChange(response.user, credentials, newCredentials);
                if (credChangeResponse.result == Authn.AuthResult.SUCCESS) {
                    updateUser(
                        new ExtMap().mput(Schema.UserIdentifiers.USER_ID, response.user.getId())
                        .mput(Schema.UserKeys.PASSWORD,
                            EnvelopePBE.encode(
                                settings.get(Schema.Settings.PBE_ALGORITHM, String.class),
                                settings.get(Schema.Settings.PBE_KEY_SIZE, Integer.class),
                                settings.get(Schema.Settings.PBE_ITERATIONS, Integer.class),
                                null,
                                newCredentials
                            )
                        )
                        .mput(Schema.UserKeys.OLD_PASSWORD, response.user.getPassword())
                        .mput(Schema.UserKeys.PASSWORD_VALID_TO,
                            DateUtils.add(
                                loginTime,
                                Calendar.DATE,
                                settings.get(Schema.Settings.PASSWORD_EXPIRATION_DAYS, Integer.class)
                            )
                        )
                    );
                    response = AuthResponse.positive();
                } else {
                    response = credChangeResponse;
                }
            }
            return response;
        } finally {
            if (response == null || response.result != Authn.AuthResult.SUCCESS) {
                delayResponse(loginTime);
            }
        }
    }

    //never return null
    private AuthResponse authenticate(
        String subject,
        String credentials,
        long loginTime
    ) throws GeneralSecurityException, SQLException, IOException {
        AuthResponse response = null;
        Schema.User user = null;

        if (response == null) {
            user = getUser(subject);
            if (user == null) {
                response = AuthResponse.negative(Authn.AuthResult.GENERAL_ERROR);
            }
        }

        synchronized (subject.intern()) { // principal known
            if (response == null) {
                response = isAuthAllowed(user, loginTime);
                if (
                    response == null &&
                    (
                        user.isNopasswd() ||
                        EnvelopePBE.check(user.getPassword(), credentials)
                    )
                ) {
                    response = AuthResponse.positive(
                        new AuthRecord(subject, getValidTo(user, loginTime)),
                        user,
                        getUserMessages(loginTime, user)
                    );
                }
                if (response == null) {
                    response = AuthResponse.negative(Authn.AuthResult.CREDENTIALS_INCORRECT, user, "credentials incorrect");
                }
            }

            if (user != null) { // update db
                if (response.result == Authn.AuthResult.SUCCESS) {
                    updateUser(
                        new ExtMap().mput(Schema.UserIdentifiers.USER_ID, user.getId())
                        .mput(Schema.UserKeys.SUCCESSFUL_LOGIN, loginTime)
                    );
                } else {
                    updateUser(
                        new ExtMap().mput(Schema.UserIdentifiers.USER_ID, user.getId())
                        .mput(Schema.UserKeys.UNSUCCESSFUL_LOGIN, loginTime)
                    );
                    user = getUser(subject);
                    checkLock(user, loginTime);
                }
            }
        }
        return response;
    }

    private Schema.User getUser(String subject) throws SQLException {
        return
            Schema.get(
                new ExtMap().mput(Schema.InvokeKeys.ENTITY, Schema.Entities.USER)
                .mput(Schema.InvokeKeys.DATA_SOURCE, ds)
                .mput(Schema.InvokeKeys.SETTINGS_RESULT, settings)
                .mput(
                    Schema.InvokeKeys.ENTITY_KEYS,
                    new ExtMap().mput(
                        Schema.UserIdentifiers.USERNAME,
                        subject
                    )
                )
            ).get(
                Schema.InvokeKeys.USER_RESULT,
                Schema.User.class
            );
    }

    private void checkLock(Schema.User user, long loginTime) throws SQLException {
        boolean consecutive;
        if (
            (
                consecutive =
                    user.getConsecutiveFailures() >= settings.get(
                        Schema.Settings.MAX_FAILURES_SINCE_SUCCESS,
                        Integer.class
                    )
            ) ||
            (
                user.countFailuresSince(
                    DateUtils.add(
                        loginTime,
                        Calendar.HOUR,
                        -settings.get(Schema.Settings.INTERVAL_HOURS, Integer.class)
                    )
                ) >= settings.get(Schema.Settings.MAX_FAILURES_PER_INTERVAL, Integer.class)
            )
        ) {
            LOG.info(
                "locking user: {} due to {}",
                user.getName(),
                consecutive ?
                "consecutive failures" :
                "interval failures"
            );

            updateUser(
                new ExtMap().mput(Schema.UserIdentifiers.USER_ID, user.getId())
                    .mput(
                        Schema.UserKeys.UNLOCK_TIME,
                        DateUtils.add(
                            loginTime,
                            Calendar.MINUTE,
                            settings.get(Schema.Settings.LOCK_MINUTES, Integer.class)
                        )
                    )
            );
        }
    }

    private void updateUser(ExtMap updateKeys) throws SQLException {
        Schema.modify(
            new ExtMap().mput(Schema.InvokeKeys.ENTITY, Schema.Entities.USER)
                .mput(Schema.InvokeKeys.MODIFICATION_TYPE, Sql.ModificationTypes.UPDATE)
                .mput(Schema.InvokeKeys.DATA_SOURCE, ds)
                .mput(Schema.InvokeKeys.SETTINGS_RESULT, settings)
                .mput(
                    Schema.InvokeKeys.ENTITY_KEYS,
                    updateKeys
                )
        );
    }

    private AuthResponse isAuthAllowed(Schema.User user, long loginTime)  {
        AuthResponse res = null;
        if (user.isDisabled()) {
            res = AuthResponse.negative(Authn.AuthResult.ACCOUNT_DISABLED, user, "account disabled");
        }

        Integer maxAttempts = settings.get(Schema.Settings.MAX_FAILURES_PER_MINUTE, Integer.class);
        if (
            res == null &&
            maxAttempts != Global.SETTINGS_SPECIAL &&
            user.countFailuresSince(
                DateUtils.add(loginTime, Calendar.MINUTE, -1)
            ) >= maxAttempts
        ) {
            res = AuthResponse.negative(Authn.AuthResult.ACCOUNT_RESTRICTION, user, "too many attempts per minute");
        }
        if (
            res == null &&
            !user.isNopasswd() &&
            loginTime > user.getPasswordValidTo()
        ) {
            res = AuthResponse.negative(Authn.AuthResult.CREDENTIALS_EXPIRED, user, "credentials expired");
        }
        if (
            res == null &&
            (
                user.getValidFrom() > loginTime ||
                user.getValidTo() < loginTime
            )
        ) {
            res = AuthResponse.negative(Authn.AuthResult.ACCOUNT_EXPIRED, user, "account expired");
        }
        if (
            res == null &&
            user.getUnlockTime() > loginTime
        ) {
            res = AuthResponse.negative(Authn.AuthResult.ACCOUNT_LOCKED, user, "account locked");
        }
        if (
            res == null &&
            Schema.User.getLoginAllowed(loginTime, user.getLoginAllowed()) == loginTime
        ) {
            res = AuthResponse.negative(Authn.AuthResult.ACCOUNT_TIME_VIOLATION, user, "account time violation");
        }
        return res;
    }

    private String getUserMessages(long loginTime, Schema.User principal) {
        StringBuilder messages = new StringBuilder();
        String separator = settings.get(Schema.Settings.MESSAGE_SEPARATOR, String.class);
        if (settings.get(Schema.Settings.PRESENT_WELCOME_MESSAGE, Boolean.class)) {
            messages.append(principal.getWelcomeMessage())
            .append(separator);

        }
        if (!StringUtils.isEmpty(settings.get(Schema.Settings.MESSAGE_OF_THE_DAY, String.class))) {
            messages.append(settings.get(Schema.Settings.MESSAGE_OF_THE_DAY, String.class))
            .append(separator);
        }
        if (
            settings.get(Schema.Settings.PASSWORD_EXPIRATION_NOTICE_DAYS, Integer.class)
            != Global.SETTINGS_SPECIAL
        ) {
            String expirationMessage =
                principal.getExpirationMessage(
                    loginTime,
                    settings.get(
                        Schema.Settings.PASSWORD_EXPIRATION_NOTICE_DAYS,
                        Integer.class
                    )
            );
            if (!StringUtils.isEmpty(expirationMessage)) {
                messages.append(expirationMessage)
                .append(separator);
            }
        }
        if (messages.length() > 0) {
            messages.setLength(messages.length() - separator.length());
        }
        return messages.toString();
    }

    private void delayResponse(long loginStart) {
        long endTime = DateUtils.add(
            loginStart,
            Calendar.SECOND,
            settings.get(
                Schema.Settings.MINIMUM_RESPONSE_SECONDS,
                Integer.class
            )
        );

        long interval;

        while ((interval = (endTime - System.currentTimeMillis())) > 0) {
            try {
                Thread.sleep(Math.max(MIN_SLEEP, interval));
                break;
            } catch (InterruptedException e) {
                LOG.warn("Interrupted while delaying response, reentering.", e);
            }
        }
    }

    private long getValidTo(Schema.User user, long loginTime) {
        List<Long> timeConstraints = new ArrayList<>(3);
        timeConstraints.add(Schema.User.getLoginAllowed(loginTime, user.getLoginAllowed()));
        timeConstraints.add(user.getValidTo());

        Integer loginMinutes = settings.get(Schema.Settings.MAX_LOGIN_MINUTES, Integer.class);
        if (loginMinutes != Global.SETTINGS_SPECIAL) {
            Calendar globalMax = DateUtils.getUtcCalendar();
            globalMax.setTimeInMillis(loginTime);
            globalMax.add(Calendar.MINUTE, loginMinutes);
            timeConstraints.add(globalMax.getTimeInMillis());
        }
        Collections.sort(timeConstraints);
        return timeConstraints.get(0);
    }


    // 동일한 문자 반복 패턴 감지 함수
    private boolean containsRepeatedPattern(String password) {
    // 1. 동일한 문자가 3번 이상 연속되는 경우 (예: aaa, 111, $$$)
        Pattern repeatedCharPattern = Pattern.compile("(.)\\1{2,}");
        Matcher matcher1 = repeatedCharPattern.matcher(password);
        if (matcher1.find()) {
            return true; // 동일 문자가 3번 이상 반복됨
        }

        // 2. 반복된 패턴 감지 (예: 123123, ababab, xyxyxy)
        Pattern repeatingPattern = Pattern.compile("(..+)\\1{1,}");
        Matcher matcher2 = repeatingPattern.matcher(password);
        if (matcher2.find()) {
            return true; // 동일한 패턴이 반복됨
        }  

        return false; // 문제 없음
    }  

    // 연속된 문자 또는 숫자 패턴이 있는지 확인하는 메서드
    private boolean containsSequentialCharacters(String password) {
        int sequenceLength = 4; // 연속된 문자 또는 숫자의 길이 (예: 1234 또는 abcd)

        // 1. 숫자에 대한 검사
        for (int i = 0; i < password.length() - sequenceLength + 1; i++) {
            boolean isSequential = true;
            for (int j = 1; j < sequenceLength; j++) {
                if (password.charAt(i + j) != password.charAt(i) + j) {
                   isSequential = false;
                   break;
                }
            }
            if (isSequential) {
                return true; // 연속적인 숫자나 문자가 발견됨
            }
         }

         // 2. 역순 숫자에 대한 검사 (예: 4321)
         for (int i = 0; i < password.length() - sequenceLength + 1; i++) {
            boolean isReverseSequential = true;
            for (int j = 1; j < sequenceLength; j++) {
                if (password.charAt(i + j) != password.charAt(i) - j) {
                   isReverseSequential = false;
                   break;
                }
            }
            if (isReverseSequential) {
               return true; // 역순 연속적인 숫자나 문자가 발견됨
            }
         }

         return false; // 연속적인 패턴이 없음
    }

    public AuthResponse checkCredChange(
        Schema.User user,
        String credentials,
        String newCredentials
    ) throws GeneralSecurityException, IOException {
        if (
            !user.isNopasswd() && !EnvelopePBE.check(user.getPassword(), credentials)
        ) {
            return AuthResponse.negative(
                Authn.AuthResult.CREDENTIALS_INCORRECT,
                user,
                "credentials incorrect"
            );
        }

        return checkCredChange(user, newCredentials);
    }
   
    // 특수문자가 포함되어 있는지 확인하는 메서드
    private boolean containsSpecialCharacter(String password) {
         Pattern specialCharPattern = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]+");
         Matcher matcher = specialCharPattern.matcher(password);
         return matcher.find();
    }

    // 101 키보드의 연속된 문자열 패턴 검사
    private boolean containsKeyboardSequence(String password) {
    
         String val_con0 = "~!@#$%^&*()_+";
         String val_con1 = "1234567890-";
         String val_con2 = "QWERTYUIOP[]\\";
         String val_con3 = "ASDFGHJKL;'\"";
         String val_con4 = "ZXCVBNM<>?";
         String val_con5 = "qwertyuiop[]{}";
         String val_con6 = "asdfghjkl;'";
         String val_con7 = "zxcvbnm,./";

         ArrayList<String> pwArr = new ArrayList<String>();
         pwArr.add(val_con0);
         pwArr.add(val_con1);
         pwArr.add(val_con2);
         pwArr.add(val_con3);
         pwArr.add(val_con4);
         pwArr.add(val_con5);
         pwArr.add(val_con6);
         pwArr.add(val_con7);
         pwArr.add(new StringBuilder(val_con0).reverse().toString());
         pwArr.add(new StringBuilder(val_con1).reverse().toString());
         pwArr.add(new StringBuilder(val_con2).reverse().toString());
         pwArr.add(new StringBuilder(val_con3).reverse().toString());
         pwArr.add(new StringBuilder(val_con4).reverse().toString());
         pwArr.add(new StringBuilder(val_con5).reverse().toString());
         pwArr.add(new StringBuilder(val_con6).reverse().toString());
         pwArr.add(new StringBuilder(val_con7).reverse().toString());

         String checkItem = "";

         // 자판 배열상 연속된 4자리 체크
         for (int i = 0; i < password.length() - 3; i++) {
             checkItem = password.charAt(i) + "" + password.charAt(i+1) + "" + password.charAt(i+2) + "" + password.charAt(i+3) + "";

             for (int j = 0; j < pwArr.size(); j++) {
                 if (pwArr.get(j).indexOf(checkItem) != -1) {
                     return true;
                 }
             }
         }

        return false; // 키보드 연속 패턴 없음
    }


    public AuthResponse checkCredChange(
        Schema.User user,
        String newCredentials
    ) throws GeneralSecurityException, IOException {
        AuthResponse response = null;
        if (newCredentials.length() < settings.get(Schema.Settings.MIN_LENGTH, Integer.class)) {
            response = AuthResponse.negative(
                Authn.AuthResult.GENERAL_ERROR,
                user,
                "new password too short"
            );

        }
        if (response == null && !complexity.check(newCredentials)) {
            response = AuthResponse.negative(
                Authn.AuthResult.GENERAL_ERROR,
                user,
                complexity.getUsage()
            );
        }
        // A password must not be identical to the user ID (case-insensitive).
        if (response == null && newCredentials.equalsIgnoreCase(user.getName())) {
             response = AuthResponse.negative(
                 Authn.AuthResult.GENERAL_ERROR,
                 user,
                 "Password cannot be identical to the user ID."
             );
        }
        if (
            response == null &&
            settings.get(
                Schema.Settings.PASSWORD_REJECT_KEYBOARD_SEQUENCES,
                Boolean.class,
                Schema.Settings.DEFAULT_PASSWORD_POLICY_OPTION
            ) &&
            containsSequentialCharacters(newCredentials)
        ) {
             response = AuthResponse.negative(
                 Authn.AuthResult.GENERAL_ERROR,
                 user,
                 "Passwords containing consecutive characters or numbers are not allowed."
             );
        }

        // 5. 특수문자 포함 여부 검사
        if (
            response == null &&
            settings.get(
                Schema.Settings.PASSWORD_REQUIRE_SPECIAL,
                Boolean.class,
                Schema.Settings.DEFAULT_PASSWORD_POLICY_OPTION
            ) &&
            !containsSpecialCharacter(newCredentials)
        ) {
            response = AuthResponse.negative(
                 Authn.AuthResult.GENERAL_ERROR,
                 user,
                 "Password must contain at least one special character."
             );
        }

	// 6. 101 키보드 연속 문자 사용 여부 검사
        if (
            response == null &&
            settings.get(
                Schema.Settings.PASSWORD_REJECT_KEYBOARD_SEQUENCES,
                Boolean.class,
                Schema.Settings.DEFAULT_PASSWORD_POLICY_OPTION
            ) &&
            containsKeyboardSequence(newCredentials)
        ) {
            response = AuthResponse.negative(
                Authn.AuthResult.GENERAL_ERROR,
                user,
                "Passwords containing consecutive characters on the keyboard are not available."
            );
        }

	// 7. 동일한 문자 또는 패턴 반복 검사
        if (
            response == null &&
            settings.get(
                Schema.Settings.PASSWORD_REJECT_REPEATED,
                Boolean.class,
                Schema.Settings.DEFAULT_PASSWORD_POLICY_OPTION
            ) &&
            containsRepeatedPattern(newCredentials)
        ) {
            response = AuthResponse.negative(
            Authn.AuthResult.GENERAL_ERROR,
            user,
            "Passwords containing repeated characters are not allowed."
            );
        }

        // 8. 이전에 사용된 비밀번호인지 검사
        if (response == null && !user.getPassword().equals("") && EnvelopePBE.check(user.getPassword(), newCredentials)) {
            response = AuthResponse.negative(Authn.AuthResult.GENERAL_ERROR, user, "new password already used");
        }
        if (response == null) {
            long passwordHistoryCutoff = DateUtils.add(
                System.currentTimeMillis(),
                Calendar.DAY_OF_MONTH,
                -settings.get(
                    Schema.Settings.PASSWORD_HISTORY_DAYS,
                    Integer.class,
                    Schema.Settings.DEFAULT_PASSWORD_HISTORY_DAYS
                )
            );
            List<Schema.User.PasswordHistory> oldPasswords = user.getOldPasswords();
            int historyLimit = settings.get(Schema.Settings.PASSWORD_HISTORY_LIMIT, Integer.class);
            for (int i = 0; i < oldPasswords.size(); i++) {
                Schema.User.PasswordHistory oldPassword = oldPasswords.get(i);
                if (
                    (oldPassword.date >= passwordHistoryCutoff || i >= oldPasswords.size() - historyLimit) &&
                    EnvelopePBE.check(oldPassword.password, newCredentials)
                ) {
                    response = AuthResponse.negative(Authn.AuthResult.GENERAL_ERROR, user, "new password already used");
                    break;
                }
            }
        }
        if (response == null) {
            response = AuthResponse.positive();
        }
        return response;
    }

    @Override
    public void update(Observable o, Object arg) {
        this.settings = (ExtMap)arg;
        int passwordHistoryDays = settings.get(
            Schema.Settings.PASSWORD_HISTORY_DAYS,
            Integer.class,
            Schema.Settings.DEFAULT_PASSWORD_HISTORY_DAYS
        );
        if (passwordHistoryDays < 0 || passwordHistoryDays > 90) {
            throw new IllegalArgumentException("PASSWORD_HISTORY_DAYS must be between 0 and 90");
        }
        Matcher m = COMPLEXITY_PATTERN.matcher(settings.get(Schema.Settings.PASSWORD_COMPLEXITY, String.class));
        boolean ok = true;
        int expectedStart = 0;
        List<Complexity.ComplexityGroup> groups = new ArrayList<>();

        while (m.find()) {
            if (m.start() != expectedStart) {
                throw new RuntimeException("Cannot parse filters");
            }

            groups.add(
                new Complexity.ComplexityGroup(
                    m.group("name"),
                    m.group("chars"),
                    Integer.parseInt(m.group("min"))
                )
            );

            expectedStart = m.end();
            ok = m.end() == m.regionEnd();
        }
        if (!ok) {
            throw new IllegalArgumentException("Cannot parse filters");
        }

        this.complexity = new Complexity(groups);;
        }
}
