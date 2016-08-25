#!/usr/bin/env node

'use strict';

var ldap = require('ldapjs');

var gPort = process.env.PORT || 3002;

var gServer = null;

var baseDN = 'ou=users,dc=example';

// data
var users = [{
    id: 'admin',
    username: 'admin',
    password: 'test',
    displayname: 'Herbert Burgermeister',
    mail: 'admin@example.org'
}, {
    id: 'normal',
    username: 'normal',
    password: 'test',
    displayname: 'Norman Default',
    mail: 'normal@example.org'
}];

// model
var user = {
    list: function (callback) {
        callback(null, users);
    },
    verify: function (username, password, callback) {
        console.log('verify:', username, password);

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

    console.log('--- Search ---');
    console.log('dn:     ', req.dn.toString());
    console.log('scope:  ', req.scope);
    console.log('filter: ', req.filter.toString());

    user.list(function (error, result){
        if (error) return next(new ldap.OperationsError(error.toString()));

        result.forEach(function (entry) {
            var tmp = {
                dn: 'dn=' + entry.id + ',' + baseDN,
                attributes: {
                    objectclass: ['user'],
                    uid: entry.id,
                    mail: entry.mail,
                    displayname: entry.username,
                    username: entry.username
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

gServer.bind(baseDN, function(req, res, next) {
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
    console.log('BaseDN:', baseDN);
    console.log('Available test users:');
    console.dir(users);
    console.log('');
});

