const express = require('express');
const http = require('http');
const io = require('socket.io');
const winston = require('winston');

const VNC = require('./vnc/vnc');

const app = express();
const server = http.createServer(app);
const ioServer = io.listen(server);

winston.configure({
	transports: [
		new winston.transports.File({
			name: 'log_error',
			filename: `${ __dirname }/../logs/error.log`,
			level: 'error'
		}),
		new winston.transports.File({
			name: 'log_info',
			filename: `${ __dirname }/../logs/info.log`
		})
	]
});

if (process.env.NODE_ENV !== 'production') {
	winston.add(winston.transports.Console);
}

app.set('views', `${ __dirname }/../views`);
app.set('view engine', 'ejs');
app.engine('html', require('ejs').renderFile);
app.use(express.static(`${ __dirname }/../public`));

ioServer.sockets.on('connection', (socket) => {
	winston.info('User Connected: ', socket.id);

	let vnc = null;

	socket.on('send', (data) => vnc.Send(data));
	socket.on('end', () => (vnc) && vnc.close());
	socket.on('vncconnect', (message) => {
		message = JSON.parse(message);

		winston.info(message);

		if (vnc) {
			const message = `Already Connected to ${ vnc.host }: ${ vnc.port }`;
			socket.emit('error', message);
			return;
		}

		vnc = new VNC();
		vnc.setCallback((data) => socket.emit((data.status) ? 'recieve' : 'error', data));
		vnc.Connect(message.host, message.port, message.security);
	});
});

app.get('/', (req, res) => {
	const ip = req.header('x-forwarded-for') || req.connection.remoteAddress;
	winston.info(`${ ip } Accessed / with ${ req.header('user-agent') }`);
	res.render('index.html');
});

const port = 80;
server.listen(port, () => winston.info(`Express server has started on port ${ port }`));
