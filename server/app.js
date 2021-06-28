require('dotenv').config()
var express = require("express");
var favicon = require("serve-favicon");
var session = require("express-session");
var bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
var request = require("request");
var path = require("path");
var fs = require("fs");

var requestIp = require('request-ip');

/**********************************************************************
    SETTING UP EXRESS SERVER
***********************************************************************/
var ifProd = process.env.ENV === 'prod';
console.log('ifProd', ifProd);

var app = express();

var useragent = require('express-useragent');
app.use(useragent.express());

app.use(require("compression")()); // gzip compression

app.disable('x-powered-by');
app.set('etag', false);
app.use(function (req, res, next) {
    res.setHeader('Surrogate-Control', 'no-store');
    res.setHeader('Cache-Control', 'private, no-cache');
    res.setHeader('Permissions-Policy', '');
    next();
});

var helmet = require("helmet");
// app.use(helmet()); // security package

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                "default-src": ["'none'"],
                "script-src": ["'self'", "data:", "https:", "'unsafe-inline'", "'unsafe-eval'"],
                "style-src": ["'self'", "data:", "https:", "'unsafe-inline'"],
                "object-src": ["'none'"],
                "img-src": ["'self'", "data:", "https:"],
                "media-src": ["'none'"],
                "frame-src": ["'none'"],
                "font-src": ["'self'"],
                "connect-src": ["'self'", "https:"],
                "form-action": ["'self'", "https:"],
                "frame-ancestors": ["'self'"],
                "worker-src": ["'self'", "blob:"],
                "base-uri": ["'self'"],
                "block-all-mixed-content": false,
                "upgrade-insecure-requests": false
            }
        },

        expectCt: {
            maxAge: 86400,
        },

        referrerPolicy: {
            policy: "same-origin",
        },

        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        },

        noSniff: true,

        originAgentCluster: true,

        dnsPrefetchControl: {
            allow: true,
        },

        ieNoOpen: true,

        frameguard: {
            action: "deny",
        },

        permittedCrossDomainPolicies: {
            permittedPolicies: "none",
        },

        hidePoweredBy: true,

        xssFilter: true

    })
);

// Session Storage Configuration:
// https://pinetools.com/random-string-generator
var secretKey = `+n&Fqv;e.+}f}x5}mx_jT4yMeA@[KZbK,SGurY/xF!ib3XE$5X?B{NHcvM3zn(Qn
}3w+B_$MuWMj].6ANGj4KXz)9XCNCUU2SN,@5h8/#u@%Q?c:7+7?:VZC[UjbLb?g
4V@WB[:6Yjj[-)H%&v,{CU$,b=!_h3Cnbv$23?[&]Wa/=)]PRry6k&}$*nAgpKYW
@E3QNu&6&g),LJa]Xdw+9+tJie$iS%(+%(Av:8@%V:a-%6Xr]WL$phfKU5Y@,V2x`;
var cookieName = ifProd ? "__Secure-DL" : "__DL";
var maxAge = 3600000 * 5;

var sessionOptions = {
    secret: secretKey,
    name: cookieName,
    proxy: ifProd,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: ifProd,
        sameSite: true,
        httpOnly: true,
        maxAge: maxAge
    }
};

if (ifProd) {
    app.set("trust proxy", 1); // trust first proxy
}

app.use(cookieParser(secretKey));
app.use(session(sessionOptions));

app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: false
    })
);




/****************************************************************************
    SET UP EXPRESS ROUTES
*****************************************************************************/
var Cryptr = require('cryptr');
// https://pinetools.com/random-string-generator
var cryptrSecret = `_Rdy=B?MAuymS!p5AkZ&hRK?gVn%nB6L:{zTzXp46b-EAp7NSZTq[[@A]ENPLUTb
    K%)#H:AxV?b&MRfpvPG4{-rW;zhh7Xy&#46axvt.?rz{@pH!i7dQJ#kpi*pgfgSx
    :[2M%h/8YW=+*MX:Ny5G=bXZ/])Bv8YWRgyu.{-[P/7haqn3jfpy;S9kb8aXJ23N
    DH=JA?Ra@yNM/CCr:5Lbw#9t@==jKQS*L,j%j]w7)n9_?y6?4-MEY8*X9Ryk9LuB`;
var cryptr = new Cryptr(cryptrSecret);

function encrypt(text) {
    try {
        return cryptr.encrypt(text)
    } catch (error) {
        console.log('encrypt', error);
    }
}

function decrypt(text) {
    try {
        return cryptr.decrypt(text)
    } catch (error) {
        console.log('decrypt', error);
    }
}

var userCookieNameUser = '__DLN';
var userCookieNamePass = '__DLP';

app.use(function (req, res, next) {

    var _host = req.get('host');
    // console.log('_host', _host, req.url);

    // DEV
    req.session.paperless_api = "http://localhost:9091";

    var _TENANTS = process.env.TENANTS && process.env.TENANTS.split(',');
    _TENANTS && _TENANTS.map(function (TENANT) {
        var _TENANT = TENANT && TENANT.split('|');
        var _TENANT_HOST_URL = _TENANT[0];
        var _TENANT_BACKEND_API = _TENANT[1];
        if (_host.includes(_TENANT_HOST_URL)) {
            req.session.paperless_api = _TENANT_BACKEND_API;
        }
    });
    next();
});



/**
 * START - No Restrictions
 */
app.use(favicon(path.join(__dirname, "../public/favicon.ico")));

app.use(
    ["/favicon.png"],
    express.static(path.join(__dirname, "../public/favicon.png"))
);


/**
* START - Static files
*/
var options = {
    dotfiles: 'ignore',
    etag: false,
    index: false,
    maxAge: '1d',
    redirect: false,
    setHeaders: function (res, path, stat) {
        res.set('x-timestamp', Date.now())
    }
}
app.use(express.static(path.join(__dirname, "../"), options));
/**
 * END - Static files
 */

/**
 * END - No Restrictions
 */




app.get("/reset-password*", function (req, res, next) {
    if (req.url.indexOf('?hash=') !== -1) {
        var userID = req.url.split('hash=').pop().split('&').shift();
        // console.log('userID', userID)
        var options = {
            url: req.session.paperless_api + "/users/getUserEmail",
            method: 'POST',
            body: {
                id: userID,
            },
            json: true
        };
        request(options, function (error, response, body) {
            console.log('reset-password body', response.body);
            if (response && response.statusCode === 200 && response.body) {
                var _response = response.body;
                var login_html = fs
                    .readFileSync(path.join(__dirname + "/../public/reset-password.html"))
                    .toString();
                if (login_html && _response.email) {
                    res.send(login_html.replace("%year%", new Date().getFullYear()).replace("%user_id%", _response.email));
                } else {
                    res.sendStatus(403);
                }
                return;
            } else {
                res.redirect("/login");
                return;
            }
        });
    } else {
        // res.sendStatus(403);
        res.redirect("/login");
        return;
    }
});

app.post("/reset-password*", function (req, res, next) {
    "use strict";
    // console.log(req.url.split('hash=').pop().split('&')[0]);
    if (req.body.user_id && req.body.user_password && req.body.confirm_user_password) {
        var options = {
            url: req.session.paperless_api + "/users/updatePassword",
            method: req.method,
            body: {
                id: req.url.split('hash=').pop().split('&')[0],
                password: req.body.user_password,
                confirmPassword: req.body.confirm_user_password
            },
            json: true
        };

        request(options, function (error, response, body) {
            console.log(response.body);
            if (response && response.statusCode === 200 && body) {
                res.redirect("/login");
                return;
            } else {
                res.redirect(req.url + "&credentials=failed");
                return;
            }
        });
    }
});




/**
 * START - Login Page
 */
app.get('/login*', function (req, res, next) {
    var cookieNameUser = req.cookies[userCookieNameUser];
    var cookieNamePass = req.cookies[userCookieNamePass];

    // console.log(cookieNameUser && cookieNamePass, cookieNameUser, cookieNamePass)
    if (cookieNameUser && cookieNamePass) {
        console.log('userCookie exist', req.url)
        var myName = decrypt(cookieNameUser);
        var myPass = decrypt(cookieNamePass);

        // console.log('myName', myName, 'myPass', myPass)

        var clientIp = requestIp.getClientIp(req);
        var _clientIp = clientIp.includes('::') ? '127.0.0.1' : clientIp;
        // console.log('_clientIp', _clientIp);

        var options = {
            url: req.session.paperless_api + "/login",
            method: 'POST',
            headers: {
                'ip': _clientIp,
                'os': req.useragent.os || '',
                'User-Agent': req.useragent.source || ''
            },
            body: {
                username: myName,
                password: myPass
            },
            json: true
        };
        request(options, function (error, response, body) {
            // console.log('/login response>', response.body);

            if (response && response.statusCode === 200 && response.body && response.body.jwtToken) {
                // console.log('jwt', response.body.jwtToken);
                console.log('|host>', req.get('host'), '|api>', req.session.paperless_api, '|ip>', _clientIp, '|u>', myName, '|ua>', req.useragent.source);

                req.session.authenticated = true;
                req.session.user_email = myName;
                req.session.jwt = response.body && response.body.jwtToken;
                req.session.ua = req.useragent.source;
                req.session.ip = _clientIp;

                res.redirect("/");
            } else {
                console.log('cookie tempered')
                res.clearCookie(userCookieNameUser);
                res.clearCookie(userCookieNamePass);
                res.clearCookie(cookieName);
                req.session.destroy();

                return res.redirect("/");
            }
        });

    } else {
        if (req.session.authenticated) {
            console.log('authenticated')
            res.clearCookie(userCookieNameUser);
            res.clearCookie(userCookieNamePass);
            res.clearCookie(cookieName);
            req.session.destroy();

            return res.redirect("/");
        }


        var login_html = fs.readFileSync(path.join(__dirname + "/../public/login.html")).toString();
        if (login_html) {
            return res.send(login_html.replace("%year%", new Date().getFullYear()));
        }
    }
    return;
});

app.post('/login', function (req, res, next) {
    "use strict";
    if (req.body.user_id && req.body.user_password) {


        // console.log('/login request>', req.body.user_id, req.body.user_password);

        var clientIp = requestIp.getClientIp(req);
        var _clientIp = clientIp.includes('::') ? '127.0.0.1' : clientIp;
        // console.log('_clientIp', _clientIp);

        var options = {
            url: req.session.paperless_api + "/login",
            method: req.method,
            headers: {
                'ip': _clientIp,
                'os': req.useragent.os || '',
                'User-Agent': req.useragent.source || ''
            },
            body: {
                username: req.body.user_id,
                password: req.body.user_password
            },
            json: true
        };
        request(options, function (error, response, body) {
            // console.log('/login response>', response.body);

            if (response && response.statusCode === 200 && body) {
                // console.log('jwt', response.body.jwtToken);
                console.log('|host>', req.get('host'), '|api>', req.session.paperless_api, '|ip>', _clientIp, '|u>', req.body.user_id, '|ua>', req.useragent.source);

                req.session.authenticated = true;
                req.session.user_email = req.body.user_id;
                req.session.jwt = response.body && response.body.jwtToken;
                req.session.ua = req.useragent.source;
                req.session.ip = _clientIp;


                var myName = encrypt(req.body.user_id);
                var myPass = encrypt(req.body.user_password);

                var userCookieOptions = {
                    sameSite: true,
                    httpOnly: true,
                    secure: ifProd,
                    maxAge: maxAge
                }

                res.cookie(userCookieNameUser, myName, userCookieOptions);
                res.cookie(userCookieNamePass, myPass, userCookieOptions);

                res.redirect("/");
            } else {
                res.redirect("/login?credentials=invalid");
                return;
            }
        });
    }
});
/**
 * END - Login Page
 */









/**
 * START - Unauthorised requrests
 */
app.use(function (req, res, next) {
    if (!req.session.authenticated && req.url != '/reset-password') {
        return res.redirect("/login");
    }

    /* if (req.session && req.session.ip) {
        var clientIp = requestIp.getClientIp(req);
        var _clientIp = clientIp.includes('::') ? '127.0.0.1' : clientIp;
        if (req.session.ip !== _clientIp) {
            console.log('session stealing: ip changed');
            console.log('|user>', req.session.user_email, '|user ip>', req.session.ip, '|request ip>', _clientIp)
            return res.redirect("/login");
        }
    } */

    /* if (req.session && req.session.ua) {
        if (req.session.ua !== req.useragent.source) {
            console.log('session stealing: browser changed');
            console.log('|user>', req.session.user_email, '|user ua>', req.session.ua, '|request ua>', req.useragent.source)
            return res.redirect("/login");
        }
    } */


    if (req.session && req.session.ua && req.session.ip) {
        var clientIp = requestIp.getClientIp(req);
        var _clientIp = clientIp.includes('::') ? '127.0.0.1' : clientIp;
        if (req.session.ua !== req.useragent.source && req.session.ip !== _clientIp) {
            console.log('session stealing: browser changed');
            console.log('|user>', req.session.user_email, '|user ua>', req.session.ua, '|request ua>', req.useragent.source)
            return res.redirect("/login");
        }
    }

    next();
});
/**
 * END - Unauthorised requrests
 */

















/**
 * START - Server variables
 */
app.get("/", function (req, res, next) {
    var options2 = {
        url: req.session.paperless_api + "/users/getDetails",
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: {
            email: req.session.user_email
        },
        json: true
    };
    request(options2, function (error2, response2, body2) {

        if (response2 && response2.statusCode === 200 && body2) {
            // console.log('user_data', body2)
            req.session.user_id = body2.user.id;
            req.session.user_data = body2;
            req.session.organization_id = body2.user.organization.organizationId;

            var index_html = fs
                .readFileSync(path.join(__dirname + "/../public/index.html"))
                .toString();
            if (index_html) {
                res.send(
                    index_html
                        .replace("___user_id___", req.session.user_id)
                        .replace("___user_data___", JSON.stringify(req.session.user_data))
                        .replace("___organization_id___", req.session.organization_id)
                );
            }


        } else {
            res.redirect("/login?credentials=invalid");
            return;
        }
    });


});
/**
 * END - Server variables
 */








/**
* START - Access Level
*/
var _accessCheck = function (_modules, _accessLevel) {
    __accessLevel = ['read', 'add', 'edit', 'delete'].includes(_accessLevel) ? _accessLevel : 'read';
    return function (req, res, next) {
        var _permissions = [];
        _modules.forEach(function (_module, index) {
            // console.log(_modules, req.session.user_data[_module])
            // return (req.session && req.session.user_data && req.session.user_data[_module] && !req.session.user_data[_module][__accessLevel]) ? res. : next();
            _permissions.push((req.session && req.session.user_data && req.session.user_data[_module] && !req.session.user_data[_module][__accessLevel]) ? false : true);
        });
        return _permissions.includes(true) ? next() : res.sendStatus(403);
    }
}
/**
 * END - Access Level
 */










/**
 * START - Status Check
 */
app.get("/statusCheck", function (req, res, next) {
    "use strict";
    // res.send(JSON.stringify(process.env));
    if (req.session.authenticated) {
        return res.sendStatus(200);
    } else {
        return res.sendStatus(401);
    }
});
/**
 * END - Status Check
 */










/**
 * START - Hierarchy Management
 */
app.get("/hierarchy", _accessCheck(['hierachyBuilder', 'assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/hierarchy",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.post("/hierarchy", _accessCheck(['hierachyBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/hierarchy",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/hierarchy", _accessCheck(['hierachyBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/hierarchy",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/hierarchy/:itemId", _accessCheck(['hierachyBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/hierarchy/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.send({ error: body });
        }
        else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Hierarchy Management
 */










/**
 * SATRT - Data Visualization
 */
app.get("/datavisualization/hierarchy", _accessCheck(['dataVisualization']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/datavisualization/hierarchy",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.get("/getDataVisualizationTrends/:tagName/:startDate/:endDate", _accessCheck(['dataVisualization']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/datavisualization/getTagTrends/" + req.params.tagName + "/" + req.params.startDate + "/" + req.params.endDate,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        gzip: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.get("/getChecklistData/:checklistId/:date/:direction/:scheduleId", _accessCheck(['dataVisualization']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/datavisualization/getChecklistData/" + req.params.checklistId + '/' + req.params.date + '/' + req.params.direction + '/' + req.params.scheduleId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * SATRT - Data Visualization
 */










/**
 * START - Template Builder
 */
app.get("/template", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.post("/template", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/template", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/template/:itemId", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.get("/template/structure/:itemId", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template/structure/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode && body) {
            res.status(response.statusCode).send(body);
        }
    });
});

app.post("/template/structure", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template/structure",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/template/structure", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template/structure",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/template/structure/:itemId", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/template/structure/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/assettemplate", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/assettemplate",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/assettemplate/:itemId", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/assettemplate/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/assettemplate/structure", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/assettemplate/structure",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/assettemplate/template", _accessCheck(['assetBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/assettemplate/template",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Template Builder
 */










/**
 * START - Checklist Builder
 */
app.get("/checklist", _accessCheck(['checklistBuilder', 'dataVisualization']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/checklist", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/structure/:itemId", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/structure/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/checklist/structure/:itemId", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/structure/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/checklist/scheduling", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/scheduling",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/checklist/:itemId", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/activate/:itemId", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/activate/" + req.params.itemId,
        method: req.method,
        body: req.body,
        json: true,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt,
            'userid': req.session.user_id
        },
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});


app.get("/checklist/deactivate/:itemId", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/deactivate/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/department", _accessCheck(['checklistBuilder', 'dataVisualization', 'userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/department/sections/:itemId", _accessCheck(['checklistBuilder', 'dataVisualization', 'userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department/sections/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/hierarchy/templatenodes", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/hierarchy/templatenodes",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist/assettemplate", _accessCheck(['checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/assettemplate",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Checklist Builder
 */








/**
 * START - Users
 */
app.get("/users", _accessCheck(['userManagement', 'checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/users",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/users/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/users/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/users", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/users",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/users", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/users",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/users/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/users/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Users
 */










/**
 * START - Groups
 */
app.get("/groups", _accessCheck(['userManagement', 'checklistBuilder']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/group",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/group", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/group/details",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/group", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/group",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/group/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/group/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/resource", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/resource",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Groups
 */









/**
 * START - Roles
 */
app.get("/roles", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/role",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/role/:roleId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/role/" + req.params.roleId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/role", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/role",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/role", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/role",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/role/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/role/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Roles
 */









/**
 * START - Departments
 */
app.get("/departments", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/department", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/department", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/department/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/department/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Departments
 */










/**
 * START - Sections
 */
app.get("/sections", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/section",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.put("/section", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/section",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/section", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/section",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.delete("/section/:itemId", _accessCheck(['userManagement']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/section/" + req.params.itemId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

/**
 * END - Sections
 */







/**
 * START - Data Collector
 */
app.get("/checklist/notification/count/:userId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/notification/count/" + req.params.userId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {

        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/data/:userId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/data/" + req.params.userId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/data/approver/:userId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/data/approver/" + req.params.userId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/claim/:checklistScheduleId/:userId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/claim/" + req.params.checklistScheduleId + '/' + req.params.userId,
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/checklist/data/approver/:userId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/data/approver/" + req.params.userId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/datavisualization/getChecklistData/:checklistScheduleId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/datavisualization/getChecklistData/" + req.params.checklistScheduleId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.get("/datacollector/getChecklistData/:checklistScheduleId", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/datacollector/getChecklistData/" + req.params.checklistScheduleId,
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist/skip", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/skip",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist/submit", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/submit",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist/save", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/save",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});

app.post("/checklist/approve", _accessCheck(['dataCollector']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/checklist/approve",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
 * END - Data Collector
 */












/**
 * START - User History
 */
app.post("/userHistory", _accessCheck(['loginHistory']), function (req, res, next) {
    "use strict";
    var options = {
        url: req.session.paperless_api + "/loginHistory",
        method: req.method,
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: req.body,
        json: true
    };
    request(options, function (error, response, body) {
        if (response && response.statusCode === 200 && body) {
            res.status(response.statusCode).send(body);
        } else {
            res.send({ error: body });
        }
    });
});
/**
* START - User History
*/











/**
 * START - Logout
 */
 app.get("/logout", function (req, res, next) {
    "use strict";
    // console.log('_logout', req.session.user_data.user.email)
    // console.log('jwt', req.session.jwt)
    var options = {
        url: req.session.paperless_api + "/users/logout",
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + req.session.jwt
        },
        body: {
            email: req.session.user_data.user.email
        },
        json: true
    };
    request(options, function (error, response, body) {
        // console.log('response', body)
        req.session.destroy();
        res.clearCookie(cookieName);

        res.clearCookie(userCookieNameUser);
        res.clearCookie(userCookieNamePass);

        res.redirect("/");
        return;
    });
});
/**
 * END - Logout
 */










/**
 * START - Not found
 */
app.use(function (req, res) {
    res.status(404).end("error");
    //res.redirect('/');
});
/**
 * END - Not found
 */









/**
 * START - Server Initialization
 */
var port = process.env.PORT || 5005;
app.listen(port, function () {
    console.log("Application running on http://localhost:%s", port);
});
/**
 * END - Server Initialization
 */
