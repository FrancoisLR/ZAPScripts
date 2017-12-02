function processMessage(utils, message) {
}

var keywords = [/Unexpected/i, /Stacktrace/i, /Error/i, /Exception/i];

function processResult(utils, fuzzResult){
	keywords.forEach(function (keyword) {
		if (fuzzResult.getHttpMessage().getResponseBody().toString().match(keyword) !== null)
			fuzzResult.addCustomState("Key Custom State", "Message Contains " + keyword + " keyword")
	});
	
	return true;
}
