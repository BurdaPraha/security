
Password Bcrypt README
======================

DESCRIPTION
-----------
This module enables bcrypt password encryption to your site.

Implementation is based on https://www.drupal.org/node/29706#comment-6445434

WARNING
-------
IT WILL NOT ENCODE BACK BCRYPT TO SHA512 IF DISABLED.
AUTHENTICATION WILL STOP WORKING FOR SOME OR ALL USERS
IF YOU DISABLE THIS MODULE.

REQUIREMENTS
------------
Drupal 7.x
PHP >= 5.3.7

INSTALLATION
------------
Simply enable the module.

HOW TO CHECK WHETHER IT WORKS?
------------------------------
Log out and log in with any user (or register a new user). Check this user's
row in "users" table. If password field starts with "$2y$", the module works.

AUTHORS
-------
Dmitriy Novikov from SmartWolverine.net - https://www.drupal.org/user/478976.

REFERENCES
----------
[1] https://www.drupal.org/node/29706#comment-6445434
