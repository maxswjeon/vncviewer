const express = require('express');
const http = require('http');
const io = require('socket.io');

const winston = require('winston');

const VNC = require('./vnc/vnc');

const app = express();
const server = http.createServer(app);
const ioServer = io.listen(server);

winston.configure({
	transports : [
		new winston.transports.File({ name : 'log_error', filename : 'logs/error.log', level : 'error' }),
		new winston.transports.File({ name : 'log_info', filename : 'logs/info.log'})
	]
});

if (process.env.NODE_ENV !== 'production') {
	winston.add(winston.transports.Console);
}

app.set('views', __dirname + '/../views');
app.set('view engine', 'ejs');
app.engine('html', require('ejs').renderFile);
app.use(express.static('public'));

ioServer.sockets.on('connection', (socket) => {

	winston.info('User Connected : ', socket.id);

	let vnc = null;

	socket.on('connect', (host, ip, security, password) => {

		if (vnc) {
			const msg = 'Already Connected to ' + vnc.host + ':' + vnc.port;
			socket.emit('error', msg);
			return;
		}

		vnc = new VNC();
		vnc.setCallback((data) => {
			if (data.status) {
				socket.emit('recieve', data);
			}
			else {
				socket.emit('error', data);
			}
		});
		vnc.Connect(host, ip, security, password);
	});

	socket.on('send', (data) => vnc.Send(data));

	socket.on('end', () => {
		if(vnc)
			vnc.Close();
	});

});

app.get('/', (req, res) => {
	const ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
	winston.info(ip +  ' Connected with ' + req.header('user-agent'));
	res.render('index.html');
});

app.listen(80, () => winston.info('Express server has started on port 80'));
