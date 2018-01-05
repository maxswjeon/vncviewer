const net = require('net');
const crypto = require('crypto');

const { ProtocolError, OptionError, ConnectionError, AuthenticationError } = require('./Errors');
const { SecurityType, ServerMessage, ClientMessage } = require('./CONSTANTS');

const desktopInfo = {
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

// PacketStatus
let ProtocolVersionHandshake = false;
let SecurityHandshake = false;
let Authentication = false;
let SecurityResult = false;
let FailReason = false;
let ServerInit = false;

let socketVersion = {
	version : -1,
	major : -1,
	minor : -1
};

let client;

class Handshake {
	static protocol (data) {
		// Check Protocol Handshake Packet
		// RFC6143 7.1.1. ProtocolVersion Handshake
		const PATTERN_HANDSHAKE = /RFB (\d\d\d)\.(\d\d\d)\n/;
		const handshakedInfo = PATTERN_HANDSHAKE.exec(data);

		// If it isn't a Protocol Handshake Packet
		if (!handshakedInfo) {
			const message = 'Hadn\'t recieved Protocol Handshake!';
			throw new ProtocolError(message);
		}

		const isBrokenData = data.length !== 12;
		if (isBrokenData) {
			const message = data.slice(data.indexOf(0x1a, 13) + 1, data.length);
			throw new ProtocolError(message);
		}

		// Parse Info & send ProtocolVersion Handshake
		const protocolVersion = parseFloat(`${ handshakedInfo[1] }.${ parseInt(handshakedInfo[2]) }`);

		setVersion(protocolVersion);

		const RFB = `RFB ${ (socketVersion.major + '').padStart(3, '0') }.${ (socketVersion.minor + '').padStart(3, '0') }\n`;
		client.write(RFB);

		ProtocolVersionHandshake = true;
	}

	static security (data, options) {
		// Check Security Handshake Packet
		// RFC6143 7.1.2. Security Handshake

		// !!IMPORTANT!!
		// The protocol is diffrent here by the version
		// RFC6143 Appendix A. Differnces in Earlier Protocol Versions
		if (socketVersion === 3.3) {
			// In Version 3.3, Server decides the security type
			security = data.readUIntBE(0, 3);
			console.warn(
				'Using Protocol version 3.3.',
				'Security option is ignored.',
				'Using server selected security : ',
				security
			);

			/*
			 * In version 3.3, there is no SecurityResult packet sent
			 * when securityType is None.
			 */
			const isNoneSecurity = options.security === SecurityType.None;
			if (isNoneSecurity) {
				Authentication = true;
				SecurityResult = true;

				return;
			}
		}

		const list = getSupportedSecurity(data);

		// If selected security option is not supported by Server
		const NO_INDEX = -1;
		const isSupportSecurityOption = NO_INDEX === list.indexOf(options.security);
		if (isSupportSecurityOption) {
			console.log(list);
			const message = 'Selected Security Option Not Supported';
			throw new ConnectionError(message);
		}

		// Challenge does not exists in None
		const isNoneSecurity = options.security === SecurityType.None;
		if (isNoneSecurity){
			Authentication = true;

			// !!IMPORTANT!!
			// The protocol is diffrent here by the version
			// RFC6143 Appendix A. Differnces in Earlier Protocol Versions
			if (socketVersion === 3.7) {
				SecurityResult = true;
			}
		}

		// Send Prefered Security Type
		client.write(String.fromCharCode(options.security));

		SecurityHandshake = true;
	}

	static authentication (data, options) {
		// Challenge VNCAuth
		// RFC6143 7.2.2. VNC Authentication

		// VNC Authentication Challenge message size is fixed to 16 bytes.
		const isBrokenData = data.length !== 16;
		if (isBrokenData){
			const message = `Challenge Message corrupted. Expected 16 bytes, Got ${ data.length }bytes.`;
			throw new ProtocolError(message);
		}

		// VNC uses mirrored password in encrypting Challenge.
		const mirroredBits = mirrorBits(Buffer.from(options.password), 'utf-8');
		const cipher = crypto.createCipheriv('des-ecb', mirroredBits, '');

		client.write(cipher.update(data));

		Authentication = true;
	}

	static securityResult (data, options) {
		// Check SecurityResult Packet
		// RFC6143 7.1.3. SecurityResult Handshake
		const result = data.readUIntBE(0, 4);
		switch (result) {
		case 0: {
			console.log('Login Successful.');
			SecurityResult = true;

			// Send ClientInit Packet
			// RFC6143 7.3.1 ClientInit
			client.write((options.shareDesktop) ? '\\1' : '\\0');
			break;
		}
		case 1: {
			// !!IMPORTANT!!
			// The protocol is diffrent here by the version
			// RFC6143 Appendix A. Differnces in Earlier Protocol Versions
			let message;
			switch (socketVersion) {
				case 3.3:
				case 3.7:
					FailReason = true;
					message = 'No reason Provided because of the Protocol Version.';
					throw new AuthenticationError(message);
				case 3.8:
				default:
					const reasonLength = data.readUIntBE(4, 4);
					message = data.slice(8, 8 + reasonLength);
					throw new AuthenticationError(message);
				}
		}
		default:
			const message = `Undefined SecurityResult :${ result }`;
			throw new ProtocolError(message);
		}
	}
}

module.exports.Connect = (options) => {
	checkOptions(options);

	client = getClient(options);

	client.on('end', () => console.log('Connection Closed by Server.'));
	client.on('data', (data) => {
		console.log();
		console.log(data);
		console.log(data.toString());

		if (!ProtocolVersionHandshake) {
			/*
			 * If we didn't get Protocol Handshaked, AND the packet isn't
			 * Protocol Handshake packet, throw error.
			 */
			Handshake.protocol(data);
		}
		else if (!SecurityHandshake) {
			/*
			 * If we didn't get Security Handshaked, AND the packet isn't
			 * Security Handshake packet, throw error.
			 */
			Handshake.security(data, options);
		}
		else if (!Authentication) {
			/*
			 * If we didn't get authenticated, AND the packet isn't
			 * Authentication Challenge packet, throw error.
			 */
			Handshake.authentication(data, options);
		}
		else if (!SecurityResult) {
			/*
			 * If we didn't get Security Result, AND the packet isn't
			 * Security Result packet, throw error.
			 */
			Handshake.securityResult(data, options);
		}
		else if (!ServerInit) {
			initalize(data);
		}
		else {
			const messageType = data[0];
			switch (messageType) {
			case ServerMessage.FramebufferUpdate:
			case ServerMessage.SetColorMapEntries:
			case ServerMessage.Bell:
			case ServerMessage.ServerCutText:
			default:
				const message = `Undefined Message Type: ${ messageType }`;
				throw new ProtocolError(message);
			}
		}
	});
}

function getClient (__option) {
	const { host, port } = __option;

	const option = { host, port };
	const logger = () => console.log(`Successfully Connected to ${ host }:${ port }`);

	const client = net.connect(option, logger);

	return client;
}

function initalize (data, options) {
	// Read ServerInit Packet
	// RFC6143 7.3.2 ServerInit
	// RFC6143 7.4 Pixel Format Data Structure
	desktopInfo.width = data.readUIntBE(0, 2);
	desktopInfo.height = data.readUIntBE(2, 2);

	// ServerPixelFormat
	desktopInfo.bitsPerPixel = data[4];
	desktopInfo.depth = data[5];
	desktopInfo.isBigEndian = data[6] !== 0;
	desktopInfo.isTrueColor = data[7] !== 0;
	desktopInfo.maxRed = data.readUIntBE(8, 2);
	desktopInfo.maxGreen = data.readUIntBE(10, 2);
	desktopInfo.maxBlue = data.readUIntBE(12, 2);
	desktopInfo.shiftRed = data[14];
	desktopInfo.shiftGreen = data[15];
	desktopInfo.shiftBlue = data[16];

	const namelen = data.readUIntBE(20, 4);
	desktopInfo.name = data.slice(24, 24 + namelen).toString();

	console.log(`Connected To Desktop: ${ desktopInfo.name }`);

	ServerInit = true;
}

// Check options
function checkOptions (options) {
	// Set Security Option to None when it isn't selected
	if (!options.hasOwnProperty('security')) {
		options.security = SecurityType.None;
	}

	const isVNC = options.security === SecurityType.VNC;
	if (!isVNC) return

	if (!options.password) {
		const message = 'Password should be provided when Security Option is VNCAuth';
		throw new OptionError(message);
	}

	// OnLiU: if options.password.length === 8 { ? }
	// Password Should be padded or sliced into 8 characters
	if (options.password.length > 8) {
		console.warn('Password Too Long. Only 8 characters are used');
		options.password = options.password.substr(0, 8);
	}
	else if (options.password.length < 8){
		options.password = options.password.padEnd(8, '\0');
	}
}

// Set version to 3.3 if not version is 3.3, 3.7 or 3.8
function setVersion (version) {
	const VERSION_LIST = [3.3, 3.7, 3.8];
	const isSupportVersion = VERSION_LIST.includes(version);
	if (isSupportVersion) {
		socketVersion.version = version;
		socketVersion.major = parseInt(version);
		socketVersion.minor = (version + '').split('.')[1];
	}
	else {
		console.warn(
			'Invalid version detected.',
			'Only Protocol version 3.3, 3.7, 3.8 are supported.\n',
			`Server Maximum version was ${ version }\n`,
			'Using Protocol version 3.3'
		);

		const baseVersion = 3.3;
		socketVersion.version = baseVersion;
		socketVersion.major = 3;
		socketVersion.minor = 3;
	}
}

function getSupportedSecurity (data) {
	// First Byte of Packet Should be U8
	const nType = data[0];

	if (nType === 0) {
		const reasonLength = data.readUIntBE(1, 4);
		const reason = data.slice(5, 5 + reasonLength);
		throw new ProtocolError(reason);
	}

	const type = [];
	for (let i = 0; i < nType; i++){
		type[i] = data[i + 1];
	}


	return type;
}

// Mirror Bits in Buffer (or Array)
function mirrorBits (data) {
	for (let i = 0; i < data.length; ++i) {
		let temp = 0;

		// Assume Byte
		for (let pos = 7; 0 < pos; --pos) {
			temp += (data[i] & 1) << pos;
			data[i] >>= 1;
		}

		data[i] = temp;
	}

	return data;
}
