module.exports.SecurityType = {
	Invalid: 0,
	None: 1,
	VNC: 2
};

module.exports.ServerMessage = {
	FramebufferUpdate: 0,
	SetColorMapEntries: 1,
	Bell: 2,
	ServerCutText: 3
};

module.exports.ClientMessage = {
	SetPixelFormat: 0,
	SetEncodings: 2,
	FramebufferUpdateRequest: 3,
	KeyEvent: 4,
	PonterEvent: 5,
	ClientCutText: 6
};
