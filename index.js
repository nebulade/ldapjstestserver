#!/usr/bin/env node

'use strict';

var ldap = require('ldapjs');

var gPort = process.env.PORT || 3002;

var gServer = null;

var baseDN = 'ou=users,dc=example';
var bindDn = 'admin';
var bindPassword = 'password';
var groupDN = 'ou=groups,dc=example';

// data
var users = [{
    id: 'admin',
    username: 'admin',
    password: 'test',
    displayname: 'Herbert Burgermeister',
    givenName: 'Herbert',
    lastName: 'Burgermeister',
    mail: 'admin@example.org',
    admin: true
}, {
    id: 'normal',
    username: 'normal',
    password: 'test',
    displayname: 'Norman Default',
    givenName: 'Norman',
    lastName: 'Default',
    mail: 'normal@example.org',
    admin: false
}];

var groups = [{
    name: 'users',
    admin: false
}, {
    name: 'admins',
    admin: true
}];

// model
var user = {
    list: function (callback) {
        callback(null, users);
    },
    verify: function (username, password, callback) {
        console.log('verify:', username, password);

        if (username === bindDn && password === bindPassword) return callback(null, {});

        var tmp = users.filter(function (u) { return u.username === username; });

        if (tmp.length === 0) return callback('not found');
        if (tmp[0].password !== password) return callback('wrong password');

        callback(null, tmp[0]);
    }
};

var logger = {
    debug: console.log,
    trace: console.log,
    warn: console.log,
    error: console.log,
};

gServer = ldap.createServer({ log: logger });

gServer.search(baseDN, function(req, res, next) {

    console.log(req)

    console.log('--- User Search ---');
    console.log('dn:     ', req.dn.toString());
    console.log('scope:  ', req.scope);
    console.log('filter: ', req.filter.toString());

    user.list(function (error, result){
        if (error) return next(new ldap.OperationsError(error.toString()));

        result.forEach(function (entry) {
            var groups = [ 'cn=users,' + groupDN ];
            if (entry.admin) groups.push('cn=admins,' + groupDN);

            var tmp = {
                dn: 'cn=' + entry.id + ',' + baseDN,
                attributes: {
                    objectclass: ['user'],
                    uid: entry.id,
                    mail: entry.mail,
                    displayname: entry.displayname,
                    sn: entry.lastName,
                    givenName: entry.givenName,
                    username: entry.username,
                    memberof: groups
                }
            };

            if (req.filter.matches(tmp.attributes)) {
                console.log('Send', tmp);
                res.send(tmp);
            }
        });

        console.log('');
        res.end();
    });
});

gServer.search(groupDN, function (req, res, next) {
    console.log('--- Group Search ---');
    console.log('dn:     ', req.dn.toString());
    console.log('scope:  ', req.scope);
    console.log('filter: ', req.filter.toString());

    user.list(function (error, result){
        if (error) return next(new ldap.OperationsError(error.toString()));

        groups.forEach(function (group) {
            var dn = ldap.parseDN('cn=' + group.name + ',ou=groups,dc=cloudron');
            var members = group.admin ? users.filter(function (entry) { return entry.admin; }) : result;

            var tmp = {
                dn: dn.toString(),
                attributes: {
                    objectclass: ['groupOfNames'],
                    cn: group.name,
                    memberuid: members.map(function(entry) { return entry.id; })
                }
            };

            if ((req.dn.equals(dn) || req.dn.parentOf(dn)) && req.filter.matches(tmp.attributes)) {
                console.log('Send', tmp);
                res.send(tmp);
            }
        });

        res.end();
    });
});

gServer.compare(groupDN, function (req, res, next) {
    console.log('--- Compare ---');
    console.log('DN: ' + req.dn.toString());
    console.log('attribute name: ' + req.attribute);
    console.log('attribute value: ' + req.value);

    res.end(true);
});

gServer.bind(baseDN, function(req, res, next) {
    console.log('--- Bind ---');
    console.log('bind DN: ' + req.dn.toString());
    console.log('bind PW: ' + req.credentials);

    var commonName = req.dn.rdns[0].attrs.cn.value;
    if (!commonName) return next(new ldap.NoSuchObjectError(req.dn.toString()));

    user.verify(commonName, req.credentials, function (error, result) {
        if (error === 'not found') return next(new ldap.NoSuchObjectError(req.dn.toString()));
        if (error === 'wrong password') return next(new ldap.InvalidCredentialsError(req.dn.toString()));
        if (error) return next(new ldap.OperationsError(error));

        console.log('login ok', result);

        res.end();
    });
});

gServer.listen(gPort, function () {
    console.log('LDAP test server running on port ' + gPort);
    console.log('');
    console.log('BindDN:        ', bindDn);
    console.log('Bind Password: ', bindPassword);
    console.log('');
    console.log('UserBaseDN:    ', baseDN);
    console.log('GroupBaseDN:   ', groupDN);
    console.log('');
    console.log('Available test users:');
    console.dir(users);
    console.log('');
    console.log('Available test groups:');
    console.dir(groups);
    console.log('');
});

