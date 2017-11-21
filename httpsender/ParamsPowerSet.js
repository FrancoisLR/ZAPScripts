// The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP, 
// including automated tools (e.g. active scanner, fuzzer, ...)

// Note that new HttpSender scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// 'initiator' is the component the initiated the request:
// 		1	PROXY_INITIATOR
// 		2	ACTIVE_SCANNER_INITIATOR
// 		3	SPIDER_INITIATOR
// 		4	FUZZER_INITIATOR
// 		5	AUTHENTICATION_INITIATOR
// 		6	MANUAL_REQUEST_INITIATOR
// 		7	CHECK_FOR_UPDATES_INITIATOR
// 		8	BEAN_SHELL_INITIATOR
// 		9	ACCESS_CONTROL_SCANNER_INITIATOR
// 		10	AJAX_SPIDER_INITIATOR
// For the latest list of values see the HttpSender class:
// https://github.com/zaproxy/zaproxy/blob/master/src/org/parosproxy/paros/network/HttpSender.java
// 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender 
// instance used to send the request.
//
// New requests can be made like this:
// msg2 = msg.cloneAll() // msg2 can then be safely changed as required without affecting msg
// helper.getHttpSender().sendAndReceive(msg2, false);
// println('msg2 response=' + msg2.getResponseHeader().getStatusCode())

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

function powerSet(s) {   
    if(s.length === 0){
        return [[]];
    }
    
    var headOfList = s.splice(0,1)[0];
    var powerSetOfListTail = powerSet(s);
    var powerSetOfListTailWithHead = powerSetOfListTail.map(function(p) { 
        var cpy = p.slice();
        cpy.push(headOfList);        
        return cpy;
    });
    
    return powerSetOfListTail.concat(powerSetOfListTailWithHead);    
}

function sendingRequest(msg, initiator, helper) {
	
}

// Loading active scanner extension interface
//var extAScan = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(org.parosproxy.paros.extension.ascan.ExtensionActiveScan.NAME);
//extAScan.getScannerParam().getExcludedParamList();

// Loading anti csrf extension interface
var extAntiCSRF = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF.NAME);
var antiCSRFTokenNames = extAntiCSRF.getAntiCsrfTokenNames();

// Loading history extension interface 
var extHist = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(
	org.parosproxy.paros.extension.history.ExtensionHistory.NAME);

function responseReceived(msg, initiator, helper) {
	// TODO: Compare with baseline	
	// TODO: Handle active scan param exclusions

	if(initiator === 6) {
		var reqParams = [];
		var mandatoryFormParams = [];

		// URL Params
		var urlParams = msg.getUrlParams();
		var urlParamsIter = urlParams.iterator();
		while (urlParamsIter.hasNext()) {
			var param = urlParamsIter.next();
			reqParams.push(["URL", param]);
		}

		// Form Params
		var formParams = msg.getFormParams();
		var formaramsIter = formParams.iterator();
		while (urlParamsIter.hasNext()) {
			var param = urlParamsIter.next();
			if(antiCSRFTokenNames.contains(param.getName())) {
				mandatoryFormParams.push(param);
			} else {
				reqParams.push(["FORM", param]);
			}
		}

		var urlParamsTreeSet = urlParams.clone();
		var formParamsTreeSet = urlParams.clone();

		powerSet(reqParams).forEach(function (_combination) {			
			var newMsg = msg.cloneAll();
			urlParamsTreeSet.clear();
			formParamsTreeSet.clear();
			print(_combination);

			_combination.forEach(function (elem) {
				switch(elem[0]) {
				case "URL":
					urlParamsTreeSet.add(elem[1]);
					break;
				case "FORM":
					formParamsTreeSet.add(elem[1]);
					break;
				}
			});

			mandatoryFormParams.forEach(function (elem) {
				formParamsTreeSet.add(elem);
			});
				
			newMsg.setGetParams(urlParamsTreeSet);
			newMsg.setFormParams(formParamsTreeSet);

			helper.getHttpSender().sendAndReceive(newMsg, false);			
			extHist.addHistory(newMsg, 15);
		});
	}
}