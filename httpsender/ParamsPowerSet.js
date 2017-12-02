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

	if(initiator === 6) { // Manual request
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
		var formParamsIter = formParams.iterator();
		while (formParamsIter.hasNext()) {
			var param = formParamsIter.next();
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
			newMsg.getRequestHeader().setHeader("Content-Length", newMsg.getRequestBody().toString().length.toString());
			
			helper.getHttpSender().sendAndReceive(newMsg, false);			
			extHist.addHistory(newMsg, 15);
		});
	}
}