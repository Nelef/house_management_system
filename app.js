var express = require('express');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);
var bodyParser = require('body-parser');
var bkfd2Password = require("pbkdf2-password");
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var hasher = bkfd2Password();
var mysql = require('mysql');
var conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'o2',
    multipleStatements: true,
    typeCast: function (field, next) {
        if (field.type == 'VAR_STRING') {
            return field.string();
        }
        return next();
    }
});

function handleDisconnect() { // Connection lost 방지
    conn.connect(function (err) {
        if (err) {
            console.log('error when connecting to db:', err);
            setTimeout(handleDisconnect, 2000);
        }
    });

    conn.on('error', function (err) {
        console.log('db error', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            return handleDisconnect();
        } else {
            throw err;
        }
    });
}

handleDisconnect();

var app = express();

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    secret: '1234DSFs@adf1234!@#$asd',
    resave: false,
    saveUninitialized: true,
    store: new MySQLStore({
        host: 'localhost', 
        port: 3306,
        user: 'root',
        password: 'root',
        database: 'o2'
    })
}));
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/logout', function (req, res) {
    req.logout();
    req.session.save(function () {
        res.redirect('/');
    });
});
app.get('/', function (req, res) {
    if (req.user && req.user.realname) {
        res.render('home', {'realname' : req.user.realname})

    } else {
        res.render('home_need_login');
    }
});
passport.serializeUser(function (user, done) {
    console.log('serializeUser', user);
    done(null, user.authId);
});
passport.deserializeUser(function (id, done) {
    console.log('deserializeUser', id);
    var sql = 'SELECT * FROM users WHERE authId=?';
    conn.query(sql, [id], function (err, results) {
        if(!results[0]) {
            console.log(err);
        } else {
            done(null, results[0]);
        }
    });
});
passport.use(new LocalStrategy(
    function (userid, password, done) {
        var uname = userid;
        var pwd = password;
        var sql = 'SELECT * FROM users WHERE authId=?';
        conn.query(sql, ['local:' + uname], function (err, results) {
            if (!results[0]) {
                console.log(!results[0]);
                return done('err', false, { message: '비밀번호가 틀렸습니다' });
            }
            var user = results[0];
            return hasher({ password: pwd, salt: user.salt }, function (err, pass, salt, hash) {
                if (hash === user.password) {
                    console.log('LocalStrategy', user);
                    done(null, user);
                } else {
                    done('ID 또는 PW가 틀렸습니다.');
                }
            });
        });
    }
));
passport.use(new FacebookStrategy({
    clientID: '1602353993419626',
    clientSecret: '6c7c3f6563511116dbc13b06f81a3985',
    callbackURL: "/auth/facebook/callback",
    profileFields: ['id', 'email', 'gender', 'link', 'locale', 'name', 'timezone', 'updated_time', 'verified', 'realname']
},
    function (accessToken, refreshToken, profile, done) {
        console.log(profile);
        var authId = 'facebook:' + profile.id;
        var sql = 'SELECT * FROM users WHERE authId=?';
        conn.query(sql, [authId], function (err, results) {
            if (results.length > 0) {
                done(null, results[0]);
            } else {
                var newuser = {
                    'authId': authId,
                    'realname': profile.realname,
                    'email': profile.emails[0].value
                };
                var sql = 'INSERT INTO users SET ?'
                conn.query(sql, newuser, function (err, results) {
                    if (err) {
                        console.log(err);
                        done('Error');
                    } else {
                        done(null, newuser);
                    }
                })
            }
        });
    }
));
app.get('/auth/facebook', passport.authenticate('facebook',
        { scope: 'email' }
    )
);
app.get('/auth/facebook/callback', passport.authenticate('facebook',
        {
            successRedirect: '/',
            failureRedirect: '/auth/login'
        }
    )
);

app.post('/auth/register', function (req, res) {
    hasher({ password: req.body.password }, function (err, pass, salt, hash) {
        var datetime = req.body.user_birth_year+"-"+req.body.user_birth_month+"-"+req.body.user_birth_day;
        var user = {
            authId: 'local:' + req.body.userid,
            userid: req.body.userid,
            realname: req.body.realname,
            password: hash,
            salt: salt,
            aptname: req.body.aptname,
            position: req.body.position,
            birth: datetime,
            zip: req.body.zip,
            address1: req.body.address1,
            address2: req.body.address2,
            phone: req.body.phone
        };
        var sql = 'INSERT INTO users SET ?';
        console.log(user);//임시 테스트
        conn.query(sql, user, function (err, results) {
            if (err) {
                console.log('err : '+err.code);
                if(err.code === 'ER_DUP_ENTRY')
                    res.render('err', {'err' : '이미 같은 id가 있습니다.'})
            } else {
                req.login(user, function (err) {
                    req.session.save(function () {
                        res.redirect('/');
                    });
                });
            }
        });
    });
});
app.get('/auth/register', function (req, res) {
    res.render('auth/register');
});

app.post('/auth/update', function (req, res) {
    hasher({ password: req.body.password }, function (err, pass, salt, hash) {
        var datetime = req.body.user_birth_year+"-"+req.body.user_birth_month+"-"+req.body.user_birth_day;
        
        var sql = 'UPDATE users SET realname=?, password=?, salt=?, aptname=?, position=?, birth=?, zip=?, address1=?, address2=?, phone=? WHERE userid=?';
        conn.query(sql, [req.body.realname,hash,salt,req.body.aptname,req.body.position,datetime,req.body.zip,req.body.address1,req.body.address2,req.body.phone,req.body.userid], function(err, result, fields) {
            if(err){
              console.log(err);
              res.status(500).send('Internal Server Error');
            } else {
              res.redirect('/');
            }
        });
    });
});
app.get('/auth/update', function (req, res) {
    if (req.user && req.user.realname) {
        var test = req.user;
        res.render('auth/update', {user_temp : req.user});
    } else {
        res.render('auth/login');
    }
});

app.post('/auth/login', passport.authenticate('local',
        {
            successRedirect: '/',
            failureRedirect: '/auth/login',
            failureFlash: false
        }
    )
);
app.get('/auth/login', function (req, res) {
    if (req.user && req.user.realname) {
        res.render('home', {'realname' : req.user.realname})
    } else {
        res.render('auth/login');
    }
});

app.post('/A/AA1', function (req, res) {
    let today = new Date();   
    let today_date = today.getFullYear() + "-" + today.getMonth()+1 + "-" + today.getDate();
    var use_check = req.body.use_check_year + "-" + req.body.use_check_month + "-" + req.body.use_check_day;
    var b_approval = req.body.b_approval_year + "-" + req.body.b_approval_month + "-" + req.body.b_approval_day;
    var user = {
        red_date: today_date,
        apt_name: req.body.apt_name,
        site_area: req.body.site_area,
        use_check: use_check,
        locat: req.body.locat,
        b_approval: b_approval,
        build_coverage: req.body.build_coverage,
        build_volum: req.body.build_volum,
        b_entity: req.body.b_entity,
        apt_corridor: req.body.apt_corridor,
        apt_terraced: req.body.apt_terraced,
        apt_house_num: req.body.apt_house_num,
        apt_enter: req.body.apt_enter,
        build_area: req.body.build_area,
        build_tarea: req.body.build_tarea,
        floor_dong: req.body.floor_dong,
        apt_dong_num: req.body.apt_dong_num,
        floor_g: req.body.floor_g,
        floor_ug: req.body.floor_ug,
        floor_house_num: req.body.floor_house_num
    };
    var sql = 'INSERT INTO aca SET ?';
    console.log(user);//임시 테스트
    conn.query(sql, user, function (err, results) {
        if (err) {
            console.log('err : ' + err);
            if (err.code === 'ER_DUP_ENTRY')
                res.render('err', { 'err': '이미 같은 id가 있습니다.' })
        } else {
            res.redirect('/A/AA1');
        }
    });
});
app.get('/A/AA1', function (req, res) {
    //전제 데이타를 조회한 후 결과를 'results' 매개변수에 저장한다.
    conn.query('select * from aca', function (error, results) {
        if (error) {
            console.log('error : ', error.message);
        } else {
            //조회결과를 'prodList' 변수에 할당한 후 'list.html' 에 전달한다.
            res.render('A/AA1', {prodList: results});
        }
    });
});

app.get('/A/AA2', function (req, res) {
    res.render('A/AA2');
});

app.listen(1530, function () {
    console.log('Connected 1530 port!!!');
});