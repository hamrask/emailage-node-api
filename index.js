const express = require('express');
const request = require('request');
const hasher = require('./sha1');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.get('/',(req,res) => {
    res.sendFile(path.join(__dirname,'public','index.html'));
});
app.post('/api/emailcheck',(req,res) => {
    if (!req.body.Email) {
        return res.send('Email Required');
    }
    var accountSId = process.env.ACCOUNT_SID;
    var authToken = process.env.AUTH_TOKEN;
    let baseUrl = '';
    if (baseUrl == undefined || (baseUrl.length) > 0 == false) {
        baseUrl = "https://sandbox.emailage.com/EmailAgeValidator/"
    }

    var oauthPostModel = {
        method: "POST",
        action: baseUrl,
        parameters: {
            format: "json",
            oauth_version: "1.0",
            oauth_consumer_key: accountSId,
            oauth_timestamp: new Date().getTime(),
            oauth_nonce: getRandomString(),
            oauth_signature_method: "HMAC-SHA1"
        }
    };

    var oauthData = getOauthData(oauthPostModel);
    var sig = hasher.b64_hmac_sha1(authToken + '&', oauthData);
    var requestUrl = oauthPostModel.action + "?" + getParameterString(oauthPostModel.parameters) + "&oauth_signature=" + percentEncode(sig);
    var options = {
        'method': 'POST',
        'url': requestUrl,
        'headers': {
          'Content-Type': 'application/json'
        },
        body: req.body.Email
      
      };
     request(options, function (error, response) { 
        if (error) throw new Error(error);
        res.send(response.body);
      });
});

const PORT = process.env.PORT||3000;

app.listen(PORT, () => console.log('Server started',PORT));


var _UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
var getRandomString = function (length) {
    length = length || 10;
    var str = "";

    while (length-- > 0) {
        str += _UnreservedChars[Math.floor(Math.random() * _UnreservedChars.length)];
    }
    return str;
};
var percentEncode = function (s) {
    s = encodeURIComponent(s);
    s = s.replace(/\!/g, "%21");
    s = s.replace(/\*/g, "%2A");
    s = s.replace(/\'/g, "%27");
    s = s.replace(/\(/g, "%28");
    s = s.replace(/\)/g, "%29");
    return s;
};
var getParameterString = function (p) {
    var s = "";
    for (var i in p) {
        s += percentEncode(i) + "=" + percentEncode(p[i]) + "&";
    }
    if (s[s.length - 1] == "&") {
        s = s.substr(0, s.length - 1);
    }
    return s;
};
var getOauthData = function (m) {
    return percentEncode(m.method.toUpperCase())
         + '&' + percentEncode(m.action)
         + '&' + percentEncode(getParameterString(m.parameters));
};
