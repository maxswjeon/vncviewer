function errorBuilder (message) {
	return class extends Error {
		constructor (message) {
			super(message);
		}
	};
}

module.exports.AuthenticationError = errorBuilder;
module.exports.ConnectionError = errorBuilder;
module.exports.OptionError = errorBuilder;
module.exports.ProtocolError = errorBuilder;
