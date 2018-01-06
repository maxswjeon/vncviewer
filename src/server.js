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
		new winston.transports.File({
			name : 'log_error',
			filename : __dirname + '/../logs/error.log',
			level : 'error'
		}),
		new winston.transports.File({
			name : 'log_info',
			filename : __dirname + '/../logs/info.log'
		})
	]
});

if (process.env.NODE_ENV !== 'production') {
	winston.add(winston.transports.Console);
}

app.set('views', __dirname + '/../views');
app.set('view engine', 'ejs');
app.engine('html', require('ejs').renderFile);
app.use(express.static( __dirname + '/../public'));

ioServer.sockets.on('connection', (socket) => {

	winston.info('User Connected : ', socket.id);

	let vnc = null;

	socket.on('vncconnect', (message) => {

		winston.info(JSON.parse(message));

		message = JSON.parse(message);

		if (vnc) {
			const msg = 'Already Connected to ' + vnc.host + ':' + vnc.port;
			socket.emit('error', msg);
			return;
		}

		vnc = new VNC.default();
		vnc.setCallback((data) => {
			if (data.status) {
				socket.emit('recieve', data);
			}
			else {
				socket.emit('error', data);
			}
		});
		vnc.Connect(message.host, message.port, message.security);
	});

	socket.on('send', (data) => vnc.Send(data));

	socket.on('end', () => {
		if(vnc)
			vnc.Close();
	});

});

app.get('/', (req, res) => {
	const ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
	winston.info(ip +  ' Accessed / with ' + req.header('user-agent'));
	res.render('index.html');
});

server.listen(80, () => winston.info('Express server has started on port 80'));
