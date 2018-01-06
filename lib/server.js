'use strict';

var express = require('express');
var http = require('http');
var io = require('socket.io');

var winston = require('winston');

var VNC = require('./vnc/vnc');

var app = express();
var server = http.createServer(app);
var ioServer = io.listen(server);

winston.configure({
	transports: [new winston.transports.File({ name: 'log_error', filename: 'logs/error.log', level: 'error' }), new winston.transports.File({ name: 'log_info', filename: 'logs/info.log' })]
});

if (process.env.NODE_ENV !== 'production') {
	winston.add(winston.transports.Console);
}

app.set('views', __dirname + '/../views');
app.set('view engine', 'ejs');
app.engine('html', require('ejs').renderFile);
app.use(express.static('public'));

ioServer.sockets.on('connection', function (socket) {

	winston.info('User Connected : ', socket.id);

	var vnc = null;

	socket.on('connect', function (host, ip, security, password) {

		if (vnc) {
			var msg = 'Already Connected to ' + vnc.host + ':' + vnc.port;
			socket.emit('error', msg);
			return;
		}

		vnc = new VNC();
		vnc.setCallback(function (data) {
			if (data.status) {
				socket.emit('recieve', data);
			} else {
				socket.emit('error', data);
			}
		});
		vnc.Connect(host, ip, security, password);
	});

	socket.on('send', function (data) {
		return vnc.Send(data);
	});

	socket.on('end', function () {
		if (vnc) vnc.Close();
	});
});

app.get('/', function (req, res) {
	var ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
	winston.info(ip + ' Connected with ' + req.header('user-agent'));
	res.render('index.html');
});

app.listen(80, function () {
	return winston.info('Express server has started on port 80');
});