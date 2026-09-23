<?php
$conf['title'] = 'LDAP application smoke test';
$conf['lang'] = 'en';
$conf['updatecheck'] = 0;
$conf['useacl'] = 1;
$conf['authtype'] = 'authldap';
$conf['superuser'] = '';
$conf['disableactions'] = 'register,resendpwd,profile';
$conf['plugin']['authldap']['server'] = 'ldap://127.0.0.1:1389';
$conf['plugin']['authldap']['version'] = 3;
$conf['plugin']['authldap']['usertree'] = 'ou=people,dc=example-app,dc=services,dc=example,dc=org';
$conf['plugin']['authldap']['grouptree'] = 'ou=groups,dc=example-app,dc=services,dc=example,dc=org';
$conf['plugin']['authldap']['userfilter'] = '(&(objectClass=inetOrgPerson)(uid=%{user}))';
$conf['plugin']['authldap']['groupfilter'] = '(&(objectClass=groupOfNames)(member=%{dn}))';
$conf['plugin']['authldap']['groupkey'] = 'cn';
$conf['plugin']['authldap']['binddn'] = 'uid=application,ou=services,dc=example-app,dc=services,dc=example,dc=org';
$conf['plugin']['authldap']['bindpw'] = 'TEST-ONLY-app-bind';
$conf['plugin']['authldap']['modPass'] = 0;
