var extHist = org.parosproxy.paros.control.Control.getSingleton().
    				getExtensionLoader().getExtension(
        				org.zaproxy.zap.extension.params.ExtensionParams.NAME);

// TODO : Support form and headers params
// TODO : Get site associated with active context
var values = extHist.getSiteParameters("localhost:8080").getParam(org.parosproxy.paros.network.HtmlParameter.Type.url, "Screen").getValues().toArray();


// Auxiliary variables/constants for payload generation.
var NUMBER_OF_PAYLOADS = values.length;
var INITIAL_VALUE = 0;
var count = INITIAL_VALUE;

// The number of generated payloads, zero to indicate unknown number.
// The number is used as a hint for progress calculations.
function getNumberOfPayloads() {
	return NUMBER_OF_PAYLOADS;
}

// Returns true if there are still payloads to generate, false otherwise.
// Called before each call to next().
function hasNext() {
	return (count < NUMBER_OF_PAYLOADS);
}

// Returns the next generated payload.
// This method is called while hasNext() returns true.
function next() {
	payload = values[count];
	count++;
	return payload;
}

// Resets the internal state of the payload generator, as if no calls to
// hasNext() or next() have been previously made.
// Normally called once the method hasNext() returns false and while payloads
// are still needed.
function reset() {
	count = INITIAL_VALUE;
}

// Releases any resources used for generation of payloads (for example, a file).
// Called once the payload generator is no longer needed.
function close() {
}