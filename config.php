<?php
/**
 * This file is copied to config.php by kick
 *
 * Placeholders (\%CONF_ENVNAME\%) are being replaced by the values found in environment.
 * See .kick.yml config_file section.
 *
 * Original file by kickstart-skel/php-app-base
 */

define("CONF_DUMMY_VALUE", "TEST CONFIG VALUE");

define("DEV_MODE", (bool)"1");
define("VERSION_INFO", "v0.1.112 (20191023-124402)");

if (DEV_MODE === true) {
    define("REDIS_CONNECT", "redis://localhost");
} else {
    define("REDIS_CONNECT", "redis://redis");
}

