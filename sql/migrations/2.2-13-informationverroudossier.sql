SET NAMES 'utf8';

ALTER TABLE `dossier` ADD `VERROU_USER_DOSSIER` bigint(20) DEFAULT NULL AFTER VERROU_DOSSIER;