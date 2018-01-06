const net = require('net');

const { SecurityType, ServerMessage, ClientMessage, MessageType } = require('./vncconst');

class VNC {

	constructor() {
		this.client = null;

		// PacketStatus
		this.PacketStatus = {
			ProtocolVersionHandshake : false,
			SecurityHandshake : false,
			Authentication : false,
			SecurityResult : false,
			ServerInit : false,
		};

		this.desktopInfo = {};
	}

	Connect(host, port, security) {
		this.security = security;
		console.log(this.PacketStatus);
		try {
			this.client = net.connect({ host : host, port : port }, () => this.callback({ status : true , error : null }));
		} catch (e) {
			this.callback({ status : false, error : e });
		}
		this.client.on('data', this._onRecieve);
		this.client.on('end', () => this.client = null);
	}

	Send(data) {
		if (!this.client) {
			this.callback({ status : false, error : 'Undefined Data Type : ' + data.type });
		}

		switch (data.type) {
		case MessageType.ProtocolVersionHandshake: {
			this.protocolVersion = data.version;
			const RFB = `RFB ${ (data.version.major + '').padStart(3, '0') }.${ (data.version.minor + '').padStart(3, '0') }\n`;
			this.client.write(RFB);
			this.PacketStatus.ProtocolVersionHandshake = true;
			break;
		}
		case MessageType.SecurityHandshake: {
			this.client.write(data.security);
			this.PacketStatus.Security = true;
			break;
		}
		case MessageType.Authentication: {
			const challenge = Buffer.from(data.challenge);
			this.client.write(challenge);
			this.PacketStatus.Authentication = true;
			break;
		}
		case MessageType.ClientInit: {
			this.client.write(data.shareDesktop ? 1 : 0);
			this.PacketStatus.SecurityResult = true;
			break;
		}
		case MessageType.SetPixelFormat: {
			let buf = Buffer.alloc(20, 0);
			buf[0] = ClientMessage.SetPixelFormat;
			this._makePixelFormat(data.info).copy(buf, 4);

			this.client.write(buf);
			break;
		}
		case MessageType.SetEncodings: {
			let buf = Buffer.alloc(4 * (data.encoding.length + 1), '\0');
			buf[0] = ClientMessage.SetEncodings;
			buf.writeUIntBE(data.encoding.length, 2, 2);
			for (let i = 0; i < data.encoding.length; ++i) {
				buf.writeIntBE(data.encoding[i], 4 + 4 * i, 4);
			}

			this.client.write(buf);
			break;
		}
		case MessageType.FramebufferUpdateRequest: {
			let buf = Buffer.alloc(10, 0);
			buf[0] = ClientMessage.FramebufferUpdateRequest;
			buf[1] = data.incremental ? 1 : 0;
			buf.writeUIntBE(data.pos.x, 2, 2);
			buf.writeUIntBE(data.pos.y, 2, 2);
			buf.writeUIntBE(data.width, 2, 2);
			buf.writeUIntBE(data.height, 2, 2);

			this.client.write(buf);
			break;
		}
		case MessageType.KeyEvent: {
			let buf = Buffer.alloc(8, 0);
			buf[0] = ClientMessage.KeyEvent;
			buf[1] = data.isDown ? 1 : 0;
			Buffer.from(data.key).copy(buf, 4);

			this.client.write(buf);
			break;
		}
		case MessageType.PointerEvent: {
			let buf = Buffer.alloc(6, 0);
			buf[0] = ClientMessage.PointerEvent;
			buf[1] = data.pointerInfo;
			buf.writeUIntBE(data.pos.x, 2, 2);
			buf.writeUIntBE(data.pos.y, 2, 2);

			this.this.client.write(buf);
			break;
		}
		case MessageType.ClientCutText: {
			let buf = Buffer.alloc(data.text.length + 8);
			buf[0] = ClientMessage.ClientCutText;
			buf.writeUIntBE(data.text.length, 4, 4);
			buf.write(data.text, 8);

			this.client.write(buf);
			break;
		}
		default: {
			this.callback({ status : false, error : 'Undefined Data Type : ' + data.type });
			return false;
		}
		}
		return true;
	}

	Close() {
		if (this.client)
			this.client.end();
	}

	setCallback(callback) {
		this.callback = callback;
	}

	_onRecieve(data) {
		console.log(this.PacketStatus);
		if (!this.PacketStatus.ProtocolVersionHandshake) {
			/*
			 * If we didn't get Protocol Handshaked, AND the packet isn't
			 * Protocol Handshake packet, throw error.
			 */
			this.callback(this._handleProtocol(data));
			return;
		}
		else if (!this.PacketStatus.SecurityHandshake) {
			/*
			 * If we didn't get Security Handshaked, AND the packet isn't
			 * Security Handshake packet, throw error.
			 */
			this.callback(this._handleSecurity(data));
			return;
		}
		else if (!this.PacketStatus.Authentication) {
			/*
			 * If we didn't get authenticated, AND the packet isn't
			 * Authentication Challenge packet, throw error.
			 */
			this.callback(this._handleAuthentication(data));
			return;
		}
		else if (!this.PacketStatus.SecurityResult) {
			/*
			 * If we didn't get Security Result, AND the packet isn't
			 * Security Result packet, throw error.
			 */
			this.callback(this._handleSecurityResult(data));
			return;
		}
		else if (!this.PacketStatus.ServerInit) {
			this.callback(this._handleServerInit(data));
			return;
		}
		else {
			const messageType = data[0];
			switch (messageType) {
			case ServerMessage.FramebufferUpdate: {
				this.callback(this._handleFrameUpdate(data));
			}
				return;
			case ServerMessage.SetColorMapEntries: {
				this.callback(this._handleSetColorMap(data));
				return;
			}
			case ServerMessage.Bell: {
				this.callback(this._handleBell());
				return;
			}
			case ServerMessage.ServerCutText: {
				this.callback(this._handleCutText(data));
				return;
			}
			default: {
				const msg = `Undefined Message Type: ${ messageType }`;
				this.callback({ status : false, error : msg });
				return;
			}
			}
		}
	}

	_handleProtocol(data) {
		// Check Protocol Handshake Packet
		// RFC6143 7.1.1. ProtocolVersion Handshake
		const PATTERN_HANDSHAKE = /RFB (\d\d\d)\.(\d\d\d)\n/;
		const versionInfo = PATTERN_HANDSHAKE.exec(data);

		// If it isn't a Protocol Handshake Packet
		if (!versionInfo) {
			const msg = 'Hadn\'t recieved Protocol Handshake!';
			return { status : false, error : msg};
		}

		const isBrokenData = data.length !== 12;
		if (isBrokenData) {
			const msg = data.slice(data.indexOf(0x1a, 13) + 1, data.length);
			return { status : false, error : msg};
		}

		let VNCVersion = {
			version : -1,
			major : parseInt(versionInfo[1]),
			minor : parseInt(versionInfo[2])
		};

		// Parse Info & send ProtocolVersion Handshake
		const protocolVersion = parseFloat(VNCVersion.major + '.' + VNCVersion.minor);

		VNCVersion.version = protocolVersion;

		return { status : true, type : MessageType.ProtocolVersionHandshake, version : VNCVersion};
	}

	_handleSecurity(data) {
		// Check Security Handshake Packet
		// RFC6143 7.1.2. Security Handshake

		// !!IMPORTANT!!
		// The protocol is diffrent here by the version
		// RFC6143 Appendix A. Differnces in Earlier Protocol Versions
		if (this.protocolVersion.version === 3.3) {
			// In Version 3.3, Server decides the security type
			let security = data.readUIntBE(0, 3);

			const isNoneSecurity = this.security === SecurityType.None;
			if (isNoneSecurity) {
				this.PacketStatus.Authentication = true;
				this.PacketStatus.SecurityResult = true;
			}

			//No responce in version 3.3
			this.PacketStatus.SecurityHandshake = true;

			return { status : true, type : MessageType.SecurityHandshake33, security : security };
		}

		const list = this._getSupportedSecurity(data);

		if (!list.status) {
			return { status : false, error : list.error  };
		}

		return { status : true, type : MessageType.SecurityHandshake, security : list.type };
	}

	_handleAuthentication(data) {
		// Challenge VNCAuth
		// RFC6143 7.2.2. VNC Authentication

		// VNC Authentication Challenge message size is fixed to 16 bytes.
		const isBrokenData = data.length !== 16;
		if (isBrokenData){
			const msg = `Challenge Message corrupted. Expected 16 bytes, Got ${ data.length }bytes.`;
			return { status : false, error : msg };
		}

		return{ status : true, type : MessageType.VNCAuthentication, challenge : data.toString() };
	}

	_handleSecurityResult(data) {
		// Check SecurityResult Packet
		// RFC6143 7.1.3. SecurityResult Handshake
		const result = data.readUIntBE(0, 4);
		switch (result) {
		case 0: {
			return { status : true, type : MessageType.SecurityResultHandshake };
		}
		case 1: {
			// !!IMPORTANT!!
			// The protocol is diffrent here by the version
			// RFC6143 Appendix A. Differnces in Earlier Protocol Versions
			let msg;
			switch (this.VNCVersion.version) {
			case 3.3:
			case 3.7: {
				msg = 'No reason Provided because of the Protocol Version.';
				return { status : false, type : MessageType.SecurityResultHandshake , error : msg};
			}
			case 3.8: {
				const reasonLength = data.readUIntBE(4, 4);
				msg = data.slice(8, 8 + reasonLength);
				return { status : false, type : MessageType.SecurityResultHandshake , error : msg};
			}
			default:{
				break;
			}
			}
			break;
		}
		default: {
			const msg = `Undefined SecurityResult :${ result }`;
			return { status : false, type : MessageType.SecurityResultHandshake , error : msg};
		}
		}
	}

	_handleServerInit(data) {
		// Read ServerInit Packet
		// RFC6143 7.3.2 ServerInit
		// RFC6143 7.4 Pixel Format Data Structure
		this.desktopInfo.width = data.readUIntBE(0, 2);
		this.desktopInfo.height = data.readUIntBE(2, 2);

		// ServerPixelFormat
		this.desktopInfo.bitsPerPixel = data[4];
		this.desktopInfo.depth = data[5];
		this.desktopInfo.isBigEndian = data[6] !== 0;
		this.desktopInfo.isTrueColor = data[7] !== 0;
		this.desktopInfo.maxRed = data.readUIntBE(8, 2);
		this.desktopInfo.maxGreen = data.readUIntBE(10, 2);
		this.desktopInfo.maxBlue = data.readUIntBE(12, 2);
		this.desktopInfo.shiftRed = data[14];
		this.desktopInfo.shiftGreen = data[15];
		this.desktopInfo.shiftBlue = data[16];

		const namelen = data.readUIntBE(20, 4);
		this.desktopInfo.name = data.slice(24, 24 + namelen).toString();

		this.PacketStatus.ServerInit = true;

		return { status : true, type : MessageType.ServerInit, info : this.desktopInfo };
	}

	_handleFrameUpdate(data) {
		let numRect = data.readUIntBE(2, 2);
		let rectArr = new Array();
		for (let i = 0; i < numRect; ++i) {
			let rect =  {};
			rect.pos = {};
			rect.pos.x = data.readUIntBE(4 + 12 * i, 2);
			rect.pos.y = data.readUIntBE(6 + 12 * i, 2);
			rect.width = data.readUIntBE(8 + 12 * i, 2);
			rect.height = data.readUIntBE(10 + 12 * i, 2);
			rect.encoding = data.readIntBE(12 + 12 * i, 4);
			rectArr.push(rect);
		}

		return { status : true, type : MessageType.FramebufferUpdate, rect : rectArr };
	}

	_handleSetColorMap(data) {
		let colorArr = new Array();

		//I don't know where it is used
		let firstColor =  data.readUIntBE(2, 2);

		let numColor = data.readUIntBE(4, 2);
		for (let i = 0; i < numColor; ++i) {
			let color = {};
			color.Red = data.readUIntBE(6 + 6 * i, 2);
			color.Green = data.readUIntBE(8 + 6 * i, 2);
			color.Blue = data.readUIntBE(10 + 6 * i, 2);
			colorArr.push(color);
		}

		return {
			status : true,
			type : MessageType.SetColorMapEntries,
			firstColor : firstColor,
			color : colorArr
		};
	}

	_handleBell() {
		return { status : true, type : MessageType.Bell };
	}

	_handleCutText(data) {
		let length = data.readUIntBE(4, 4);
		let text = data.slice(8, 8 + length).toString();

		return { status : true, type : MessageType.ServerCutText, text : text };
	}

	_getSupportedSecurity(data) {
		// First Byte of Packet Should be U8
		const nType = data[0];

		if (nType === 0) {
			const reasonLength = data.readUIntBE(1, 4);
			const reason = data.slice(5, 5 + reasonLength);
			return { status : false, error : reason };
		}

		const type = [];
		for (let i = 0; i < nType; i++){
			type[i] = data[i + 1];
		}


		return { status : true, type : type };
	}

	_makePixelFormat(data) {
		//RFC6143 7.4. Pixel Format Data Structure
		let buf = Buffer.alloc(16, 0);
		buf[0] = data.bitsPerPixel;
		buf[1] = data.depth;
		buf[2] = data.isBigEndian ? 1 : 0;
		buf[3] = data.isTrueColor ? 1 : 0;
		buf.writeUIntBE(data.maxRed, 4, 2);
		buf.writeUIntBE(data.maxGreen, 6, 2);
		buf.writeUIntBE(data.maxBlue, 8, 2);
		buf[10] = data.shiftRed;
		buf[11] = data.shiftGreen;
		buf[12] = data.shiftBlue;

		return buf;
	}

}

exports.default = VNC;
