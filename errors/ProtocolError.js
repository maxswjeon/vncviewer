module.exports = class ProtocolError extends Error {
	constructor (message) {
		// Providing default message and overriding status code.
		super(message);
	}
};
