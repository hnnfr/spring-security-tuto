INSERT INTO "USERS" (EMAIL, PWD, ROLE) VALUES ('userA@example.com', '12345', 'USER');
INSERT INTO "USERS" (EMAIL, PWD, ROLE) VALUES ('userB@example.com', '12345', 'USER');
INSERT INTO "USERS" (EMAIL, PWD, ROLE) VALUES ('superuser@example.com', '12345', 'ADMIN');

INSERT INTO "TOPIC" (USER_ID, NAME) VALUES (1, 'JO 2024');
INSERT INTO "TOPIC" (USER_ID, NAME) VALUES (1, 'Vaccins Covid');
INSERT INTO "TOPIC" (USER_ID, NAME) VALUES (2, 'Spring Cloud');
INSERT INTO "TOPIC" (USER_ID, NAME) VALUES (3, 'Guerre du Vietnam');

INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (1, 1, 'Trop fort la France', 'PUBLIC');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (2, 1, 'Cérémonie de fermeture null', 'PUBLIC');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (1, 2, 'Beaucoup d''incertitude', 'PUBLIC');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (2, 2, 'Es-tu anti-vaccin?', 'PROTECTED');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (2, 3, 'Où je dois commencer?', 'PUBLIC');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (2, 3, 'It''s my future job!', 'PUBLIC');
INSERT INTO "OPINION" (USER_ID, TOPIC_ID, DETAILS, SCOPE) VALUES (3, 4, 'Mon père était là-bas pendant 2 ans', 'PUBLIC');
