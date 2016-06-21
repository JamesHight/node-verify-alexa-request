verify-alexa-request
----------------------------

Validate an Amazon Alexa skill request.  The certificate(s) used to validate the request signature are stored using stale-lru-cache to speed up response time.


````bash
npm install verify-alexa-request
````


````javascript
var VerifyAlexaRequest  = require('verify-alexa-request');
var verifyAlexaRequest = new VerifyAlexaRequest({ applicationId: 'foo' });


verifyAlexaSkillRequest.verify(signaturecertchainurl, signature, req.body, function(err) {
	if (err) console.log('Invalid request');
	else console.log('Valid request');
});

````
