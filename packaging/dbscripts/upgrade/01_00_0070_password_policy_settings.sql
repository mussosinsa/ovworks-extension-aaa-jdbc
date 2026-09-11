INSERT INTO settings(uuid, name, value, description) VALUES
('77cd7071-1d6d-48ba-ac07-ddf50d03329d', 'PASSWORD_HISTORY_DAYS', 90, 'reject passwords used in the previous X days; valid range is 0 through 90'),
('fd5e8737-a93f-4765-a229-6ecf64d3b91d', 'PASSWORD_REJECT_REPEATED', TRUE, 'reject repeated characters and repeated patterns'),
('b5b1937e-4473-4333-9639-26f10dc4d9c8', 'PASSWORD_REJECT_KEYBOARD_SEQUENCES', TRUE, 'reject four-character alphabetic, numeric, and keyboard sequences'),
('eb4c52e7-0e8a-45f5-9825-61f9b9ee029b', 'PASSWORD_REQUIRE_SPECIAL', TRUE, 'require at least one special character');

UPDATE settings
SET value = 'UPPERCASE:chars=ABCDEFGHIJKLMNOPQRSTUVWXYZ::min=1::LOWERCASE:chars=abcdefghijklmnopqrstuvwxyz::min=1::NUMBERS:chars=0123456789::min=1::'
WHERE uuid = 'b55243d1-27b5-49bf-8436-67d5ada33975';

UPDATE settings
SET value = 12
WHERE uuid = '24e7de2f-a714-4f3e-8f64-13bc6ee7525b';
