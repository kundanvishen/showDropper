/*
 * The MIT License (MIT)
 * Copyright (c) 2017 Kundan Singh
 * https://kundan.me
 * 
 */

var CONFIG = require('./config.local.json');
var mongoConnectionString = CONFIG.MONGO_CONNECTION_STRING;


var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var async = require('async');
var request = require('request');
var xml2js = require('xml2js');
var session = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var _ = require('lodash');
var agenda = require('agenda')({ db: { address: mongoConnectionString } });
var sugar = require('sugar');
var nodemailer = require('nodemailer');

var showSchema = new mongoose.Schema({
    _id: Number,
    name: String,
    airsDayOfWeek: String,
    airsTime: String,
    firstAired: Date,
    genre: [String],
    network: String,
    overview: String,
    rating: Number,
    ratingCount: Number,
    status: String,
    poster: String,
    subscribers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    episodes: [{
        season: Number,
        episodeNumber: Number,
        episodeName: String,
        firstAired: Date,
        overview: String
    }]
});

var userSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String
});

userSchema.pre('save', function(next) {
    var user = this;
    if (!user.isModified('password')) return next();
    bcrypt.genSalt(10, function(err, salt) {
        if (err) return next(err);
        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

var User = mongoose.model('User', userSchema);
var Show = mongoose.model('Show', showSchema);

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, '-password', function(err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy({ usernameField: 'email' }, function(email, password, done) {
    User.findOne({ email: email }, function(err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);
        user.comparePassword(password, function(err, isMatch) {
            if (err) return done(err);
            if (isMatch) return done(null, user);
            return done(null, false);
        });
    });
}));


function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) next();
    else res.send(401);
}


// mongoose.connect('localhost');
mongoose.connect(mongoConnectionString);

// define agenda to send email alert to users
agenda.define('send email alert', function(job, done) {
    Show.findOne({ name: job.attrs.data }).populate('subscribers').exec(function(err, show) {
        var emails = show.subscribers.map(function(user) {
            return user.email;
        });

        var upcomingEpisode = show.episodes.filter(function(episode) {
            return new Date(episode.firstAired) > new Date();
        })[0];

        var smtpTransport = nodemailer.createTransport('SMTP', {
            service: 'SendGrid',
            auth: { user: 'hslogin', pass: 'hspassword00' }
        });

        var mailOptions = {
            from: 'Fred Foo ✔ <foo@blurdybloop.com>',
            to: emails.join(','),
            subject: show.name + ' is starting soon!',
            text: show.name + ' starts in less than 2 hours on ' + show.network + '.\n\n' +
                'Episode ' + upcomingEpisode.episodeNumber + ' Overview\n\n' + upcomingEpisode.overview
        };

        smtpTransport.sendMail(mailOptions, function(error, response) {
            console.log('Message sent: ' + response.message);
            smtpTransport.close();
            done();
        });
    });
});

agenda.start();

agenda.on('start', function(job) {
    console.log("Job %s starting", job.attrs.name);
});

agenda.on('complete', function(job) {
    console.log("Job %s finished", job.attrs.name);
});

var app = express();

app.set('port', process.env.PORT || 3000);
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());

app.use(session({ secret: 'keyboard cat' }));
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

app.use(function(req, res, next) {
    if (req.user) {
        res.cookie('user', JSON.stringify(req.user));
    }
    next();
});

app.post('/api/login', passport.authenticate('local'), function(req, res) {
    res.cookie('user', JSON.stringify(req.user));
    res.send(req.user);
});

app.post('/api/signup', function(req, res, next) {
    var user = new User({
        email: req.body.email,
        password: req.body.password
    });
    user.save(function(err) {
        if (err) return next(err);
        res.send(200);
    });
});

app.get('/api/logout', function(req, res, next) {
    req.logout();
    res.send(200);
});


// route to show all shows on basis of queris
app.get('/api/shows', function(req, res, next) {
    var query = Show.find();
    if (req.query.genre) {
        query.where({ genre: req.query.genre });
    } else if (req.query.alphabet) {
        query.where({ name: new RegExp('^' + '[' + req.query.alphabet + ']', 'i') });
    } else {
        query.limit(12);
    }
    query.exec(function(err, shows) {
        if (err) return next(err);
        res.send(shows);
    });
});

// route for single show
app.get('/api/shows/:id', function(req, res, next) {
    Show.findById(req.params.id, function(err, show) {
        if (err) { return next(err); }
        res.send(show);
    });
});

// add new TV show to the database
app.post('/api/shows', function(req, res, next) {
    var apiKey = CONFIG.TVDB_API_KEY;
    var parser = xml2js.Parser({
        explicitArray: false,
        normalizeThings: true
    });

    // normalize all tags to lowercase and disable
    // conversion to arrays when there is only one child element
    var seriesName = req.body.showName
        .toLowerCase()
        .replace(/ /g, '_')
        .replace(/[^\w-]+/g, '');

    async.waterfall([
        function(callback) {
            request.get('http://thetvdb.com/api/GetSeries.php?seriesname=' + seriesName, function(error, response, body) {
                if (error) return next(error);
                parser.parseString(body, function(err, result) {
                    if (!result.Data.Series) {
                        return res.send(404, { message: req.body.showName + ' was not found..' });
                    }
                    var seriesId = result.Data.Series.seriesid || result.Data.Series[0].seriesid;
                    callback(err, seriesId);
                });
            });
        },
        function(seriesId, callback) {
            request.get('http://thetvdb.com/api/' + apiKey + '/series/' + seriesId + '/all/en.xml', function(error, response, body) {
                if (error) return next(error);
                parser.parseString(body, function(err, result) {

                    var series = result.Data.Series;
                    var episodes = result.Data.Episode;
                    var show = new Show({
                        _id: series.id,
                        name: series.Seriesname,
                        airsDayOfWeek: series.Airs_Time,
                        firstAired: series.FirstAired,
                        genre: series.Genre.split('|').filter(Boolean),
                        network: series.Network,
                        overview: series.Overview,
                        rating: series.Rating,
                        ratingCount: series.RatingCount,
                        runtime: series.Runtime,
                        status: series.Status,
                        poster: series.poster,
                        episodes: []
                    });
                    _.each(episodes, function(episode) {
                        show.episodes.push({
                            season: episode.SeasonNumber,
                            episodeNumber: episode.EpisodeNumber,
                            episodeName: episode.EpisodeName,
                            firstAired: episode.FirstAired,
                            overview: episode.Overview
                        });
                    });
                    callback(err, show);
                });
            });
        },
        function(show, callback) {
            var url = 'http://thetvdb.com/banners/' + show.poster;
            request({ url: url, encoding: null }, function(error, response, body) {
                show.poster = 'data:' + response.headers['content-type'] + ';base64,' + body.toString('base64');
                callback(error, show);
            });
        }
    ], function(err, show) {
        if (err) return next(err);
        show.save(function(err) {
            if (err) {
                if (err.code == 11000) {
                    return res.send(409, { message: show.name + ' already exists.' });
                }
                return next(err);
            }
            var alertDate = Date.create('Next ' + show.airsDayOfWeek + ' at ' + show.airsTime).rewind({ hour: 2 });
            agenda.schedule(alertDate, 'send email alert', show.name).repeatEvery('1 week');
            res.send(200);
        });
    });
});

app.post('/api/subscribe', ensureAuthenticated, function(req, res, next) {
    Show.findById(req.body.showId, function(err, show) {
        if (err) return next(err);
        show.subscribers.push(req.user.id);
        show.save(function(err) {
            if (err) return next(err);
            res.send(200);
        });
    });
});

app.post('/api/unsubscribe', ensureAuthenticated, function(req, res, next) {
    Show.findById(req.body.showId, function(err, show) {
        if (err) return callback(err);
        var index = show.subscribers.indexOf(req.user.id);
        show.subscribers.splice(index, 1);
        show.save(function(err) {
            if (err) return next(err);
            res.send(200);
        });
    });
});


// redirect route
app.get('*', function(req, res) {
    res.redirect('/#' + req.originalUrl);
});

// error handling middleware
app.use(function(err, req, res, next) {
    console.error(err.stack);
    res.send(500, { message: err.message });
});

app.listen(app.get('port'), function() {
    console.log('Express server listening on port ' + app.get('port'));
});