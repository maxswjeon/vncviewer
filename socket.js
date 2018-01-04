const net = require('net');
const crypto = require('crypto');

const ProtocolError = require('./errors/ProtocolError');
const OptionError = require('./errors/OptionError');
const ConnectionError = require('./errors/ConnectionError');
const AuthenticationError = require('./errors/AuthenticationError');

//SecurityType Constants
const SecurityType = {
	Invalid : 0,
	None : 1,
	VNC : 2
};

//Server Message Constants
const ServerMessage = {
	FramebufferUpdate : 0,
	SetColorMapEntries : 1,
	Bell : 2,
	ServerCutText : 3
};

//Client Message Constants
const ClientMessage = {
	SetPixelFormat : 0,
	SetEncodings : 2,
	FramebufferUpdateRequest : 3,
	KeyEvent : 4,
	PonterEvent : 5,
	ClientCutText : 6
};

let majorVersion;
let minorVersion;
let desktopInfo = {
	width : -1,
	height : -1,
	bitsPerPixel : -1,
	depth : -1,
	isBigEndian : false,
	isTrueColor : false,
	maxRed : -1,
	maxGreen : -1,
	maxBlue : -1,
	shiftRed : -1,
	shiftGreen : -1,
	shiftBlue : -1,
	name: null,
};

//PacketStatus
let ProtocolVersionHandshake = false;
let SecurityHandshake = false;
let Authentication = false;
let SecurityResult = false;
let FailReason = false;
let ServerInit = false;


exports.Connect = function (options) {

	checkOptions(options);

	let client = net.connect({
		host: options.host,
		port: options.port
	}, function () {
		console.log('Successfully Connected to ' + options.host + ':' + options.port);
	});

	client.on('data', function (data) {
		console.log();
		console.log(data);
		console.log(data.toString());

		let regex;

		/*
		 * If we didn't get Protocol Handshaked, AND the packet isn't
		 * Protocol Handshake packet, throw error.
		 */
		if (!ProtocolVersionHandshake) {
			//Check Protocol Handshake Packet
			//RFC6143 7.1.1. ProtocolVersion Handshake
			regex = /RFB (\d\d\d)\.(\d\d\d)\n/.exec(data);

			//If it isn't a Protocol Handshake Packet
			if (!regex) {
				throw new ProtocolError("Hadn't recieved Protocol Handshake!");
			}

			if (data.length !== 12) {
				throw new ProtocolError(
					data.slice(data.indexOf(0x1a, 13) + 1, data.length).toString());
			}

			//Parse Info & send ProtocolVersion Handshake
			setVersion(parseInt(regex[1]), parseInt(regex[2]));

			client.write('RFB ' +
				('000' + majorVersion).substring(('' + majorVersion).length) +
				'.' +
				('000' + minorVersion).substring(('' + minorVersion).length) + '\n');


			ProtocolVersionHandshake = true;

			//End of Parsing Packet
			return;
		}

		/*
		 * If we didn't get Security Handshaked, AND the packet isn't
		 * Security Handshake packet, throw error.
		 */
		if (!SecurityHandshake) {
			//Check Security Handshake Packet
			//RFC6143 7.1.2. Security Handshake

			//!!IMPORTANT!!
			//The protocol is diffrent here by the version
			//RFC6143 Appendix A. Differnces in Earlier Protocol Versions
			if (majorVersion === 3) {

				//In Version 3.3, Server decides the security type
				if (minorVersion === 3) {
					security = data.readUIntBE(0, 3);
					console.warn('Using Protocol version 3.3. '
								+ 'Security option is ignored. '
								+ 'Using server selected security : '
								+ options.securityType.ToString());

					/*
					* In version 3.3, there is no SecurityResult packet sent
					* when securityType is None.
					*/
					if (options.security === SecurityType.None){
						Authentication = true;
						SecurityResult = true;

						return;
					}
				}
			}

			let list = getSupportedSecurity(data);

			//If selected security option is not supported by Server
			if (list.indexOf(options.security) === -1) {
				throw new ConnectionError('Selected Security Option Not Supported');
			}

			//Challenge does not exists in None
			if (options.security === SecurityType.None){
				Authentication = true;

				//!!IMPORTANT!!
				//The protocol is diffrent here by the version
				//RFC6143 Appendix A. Differnces in Earlier Protocol Versions
				if (majorVersion == 3) {

					//In Version 3.7, Server does not send SecurityResult Message
					if (minorVersion == 7) {
						SecurityResult = true;
					}
				}
			}

			//Send Prefered Security Type
			client.write(String.fromCharCode(options.security));

			SecurityHandshake = true;

			//End of Parsing Packet
			return;
		}

		/*
		 * If we didn't get authenticated, AND the packet isn't
		 * Authentication Challenge packet, throw error.
		 */
		if (!Authentication) {
			//Challenge VNCAuth
			//RFC6143 7.2.2. VNC Authentication

			//VNC Authentication Challenge message size is fixed to 16 bytes.
			if (data.length !== 16){
				throw new ProtocolError('Challenge Message corrupted. Expected 16 bytes, Got '
										+ data.length + ' bytes.');
			}

			//VNC uses mirrored password in encrypting Challenge.
			let cipher = crypto.createCipheriv('des-ecb',
					mirrorBits(Buffer.from(options.password), 'utf-8'), '');
			let c = cipher.update(data);

			client.write(c);

			Authentication = true;

			//End of Parsing Packet
			return;
		}

		/*
		 * If we didn't get Security Result, AND the packet isn't
		 * Security Result packet, throw error.
		 */
		if (!SecurityResult){
			//Check SecurityResult Packet
			//RFC6143 7.1.3. SecurityResult Handshake

			let result = data.readUIntBE(0, 4);

			//00 00 00 00 is OK
			if (result === 0) {
				console.log('Login Successful.');
				SecurityResult = true;

				//Send ClientInit Packet
				//RFC6143 7.3.1 ClientInit
				client.write(options.shareDesktop ? '\1' : '\0');

				//End of Parsing Packet
				return;
			}

			else if(result === 1) {
				//!!IMPORTANT!!
				//The protocol is diffrent here by the version
				//RFC6143 Appendix A. Differnces in Earlier Protocol Versions
				if (majorVersion == 3) {

					//In version 3.3, Server does not send reason of failure
					if (minorVersion == 3) {
						FailReason = true;
						throw new AuthenticationError('No reason Provided because of the Protocol Version.');
					}

					//In version 3.7, Server does not send reason of failure
					if (minorVersion == 7) {
						FailReason = true;
						throw new AuthenticationError('No reason Provided because of the Protocol Version.');
					}

					if (minorVersion == 8) {
						let reasonLength = data.readUIntBE(4, 4);
						let reason = data.slice(8, 8 + reasonLength).toString();
						throw new AuthenticationError(reason);
					}
				}
			}

			else {
				throw new ProtocolError('Not defined SecurityResult : ' + result);
			}

			//End of Parsing Packet
			return;
		}

		if (!ServerInit) {
			//Read ServerInit Packet
			//RFC6143 7.3.2 ServerInit
			//RFC6143 7.4 Pixel Format Data Structure
			desktopInfo.width = data.readUIntBE(0, 2);
			desktopInfo.height = data.readUIntBE(2, 2);

			//ServerPixelFormat
			desktopInfo.bitsPerPixel = data[4];
			desktopInfo.depth = data[5];
			desktopInfo.isBigEndian = data[6] === 0 ? false : true;
			desktopInfo.isTrueColor = data[7] === 0 ? false : true;
			desktopInfo.maxRed = data.readUIntBE(8, 2);
			desktopInfo.maxGreen = data.readUIntBE(10, 2);
			desktopInfo.maxBlue = data.readUIntBE(12, 2);
			desktopInfo.shiftRed = data[14];
			desktopInfo.shiftGreen = data[15];
			desktopInfo.shiftBlue = data[16];

			let namelen = data.readUIntBE(20, 4);
			desktopInfo.name = data.slice(24, 24 + namelen).toString();

			console.log('Connected To Desktop : ' + desktopInfo.name);

			ServerInit = true;

			//End of Parsing Packet
			return;
		}

		let messageType = data[0];
		if (messageType === ServerMessage.FramebufferUpdate) {

		}
		else if (messageType === ServerMessage.SetColorMapEntries) {

		}
		else if (messageType === ServerMessage.Bell) {

		}
		else if (messageType === ServerMessage.ServerCutText) {

		}
		else {
			throw new ProtocolError('Undefined Message Type : ' + messageType);
		}

  	});
	client.on('end', function() {
			console.log('Connection Closed by Server.');
	});
}

//Check options
function checkOptions(options) {
	//Set Security Option to None when it isn't selected
	if (!options.hasOwnProperty('security')) {
		options.security = SecurityType.None;
	}

	if (options.security === SecurityType.VNC) {
		if (!options.password) {
			throw new OptionError('Password should be provided when Security Option is VNCAuth');
		}

		//Password Should be padded or sliced into 8 characters
		if (options.password.length > 8) {
			console.warn('Password Too Long. Only 8 characters are used');
			options.password = options.password.substr(0, 8);
		}
		else if (options.password.length < 8){
			options.password = options.password.padEnd(8, '\0');
		}
	}
}


function setVersion(major, minor) {
	//Set version to 3.3 if not version is 3.3, 3.7 or 3.8

	majorVersion = 3;

	//regex[1] has the Major Version
	if (major !== 3) {
		console.warn('Invalid version detected. '
		 			+ 'Only Protocol version 3.3, 3.7, 3.8 are supported.\n'
					+ 'Server Maximum version was ' + major + '.' + minor + '\n'
					+ 'Using Protocol version 3.3');
		minorVersion = 3;
	}

	//regex[2] has the Minor version
	if (minor === 3 || minor === 7 || minor === 8) {
		minorVersion = minor;
	}
	else {
		console.warn('Invalid version detected. '
		 			+ 'Only Protocol version 3.3, 3.7, 3.8 are supported.\n'
					+ 'Server Maximum version was ' + major + '.' + minor + '\n'
					+ 'Using Protocol version 3.3');
		minorVersion = 3;
	}
}

function getSupportedSecurity(data) {

	//First Byte of Packet Should be U8
	let nType = data[0];

	if (nType == 0) {
		let reasonLength = data.readUIntBE(1, 4);
		let reason = data.slice(5, 5 + reasonLength).toString();
		throw new ProtocolError(reason);
	}

	let type = new Array(nType);
	for (let i = 1; i <= nType; ++i){
		type[i - 1] = data[i];
	}

	return type;
}

//Mirror Bits in Buffer (or Array)
function mirrorBits(data) {
	for (let i = 0; i < data.length; ++i) {
		let temp = 0;

		//Assume Byte
		for (let pos = 7; pos > 0; --pos) {
			temp += ((data[i] & 1) << pos);
			data[i] >>= 1;
		}

		data[i] = temp;
	}

	return data;
}
