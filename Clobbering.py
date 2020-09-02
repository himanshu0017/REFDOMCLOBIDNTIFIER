from burp import IBurpExtender, IScanIssue, IScannerCheck, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener
from java.io import PrintWriter
from java.lang import RuntimeException
from uuid import uuid4
import urllib2
import array
import re
from java.net import URL
import json
import hashlib
import os.path
import string
import random

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):

        global burp_callbacks
        burp_callbacks = callbacks
        global burp_helpers
        burp_helpers = burp_callbacks.getHelpers()
        burp_callbacks.setExtensionName("XSS/HTML Injection")
        
        self.stdout = PrintWriter(burp_callbacks.getStdout(), True)
        
        self.println("XSS/HTMl")
        
        burp_callbacks.registerScannerCheck(self)
        burp_callbacks.registerProxyListener(self)
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        textIssue = ""
        tags = ""
        s = 0
        f = 0
        Special_Charss_event_handlers = ["'\"", "<"," onpointermove=alert()>", "\\\\'xss", "\\\\\"ggg", "\\",">"]
        payload_all = ""
        rand_str = "img"
        for payload in Special_Charss_event_handlers:
            payload_all = payload_all+rand_str+payload
        #payload_all = payload_all+rand_str
        payload_bytes = burp_helpers.stringToBytes(payload_all)
        attack = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(payload_bytes))
        response = attack.getResponse()
        response_str = burp_helpers.bytesToString(response)
        if_found_payload = ""
        non_encoded_symbols = ""
        severity = "Low"
        for check_payload in Special_Charss_event_handlers:
            if_found_payload = rand_str+check_payload
            if if_found_payload in response_str:
                non_encoded_symbols = non_encoded_symbols+"   "+check_payload.replace('<', '&lt;')
                s = s+1
                f = 1
        if s > 2: severity = "Medium"
        if s > 3: severity = "High"
        if non_encoded_symbols == "   \\\\'xss":
            severity = "Information"
        if non_encoded_symbols != '':
            textIssue = textIssue + "<br><br>Symbols not encoded: "+non_encoded_symbols+"<br>"
        if 'onpointermove' not in response_str and f == 1:
            textIssue = textIssue + '<br><h3>Event handler blocked HTML INJECTION is there</h3>'
        if f == 1:
            return [CustomScanIssue(burp_helpers.analyzeRequest(attack).getUrl(), "XSS", 134217728, severity, "Certain", None, None, textIssue, None, [attack], attack.getHttpService())]
        """
        textIssue1 = ""
        s1 = 0
        f1 = 0
        Special_Charss_event_handlers = ["'\"", "<"," href=x>", "\\\\'xss", "\\\\\"ggg", "\\",">"]
        payload_all = ""
        rand_str = "a"
        for payload in Special_Charss_event_handlers:
            payload_all = payload_all+rand_str+payload
        #payload_all = payload_all+rand_str
        payload_bytes = burp_helpers.stringToBytes(payload_all)
        attack = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(payload_bytes))
        response = attack.getResponse()
        response_str = burp_helpers.bytesToString(response)
        if_found_payload = ""
        non_encoded_symbols = ""
        severity = "Low"
        for check_payload in Special_Charss_event_handlers:
            if_found_payload = rand_str+check_payload
            if if_found_payload in response_str:
                non_encoded_symbols = non_encoded_symbols+"   "+check_payload.replace('<', '&lt;')
                s1 = s1+1
                f1 = 1
        if s1 > 2: severity = "Medium"
        if s1 > 3: severity = "High"
        if non_encoded_symbols == "   \\\\'xss":
            severity = "Information"
        if non_encoded_symbols != '':
            textIssue1 = textIssue1 + "<br><br>Symbols not encoded  : "+non_encoded_symbols+"<br>"
        if f1 == 1:
            return [CustomScanIssue(burp_helpers.analyzeRequest(attack).getUrl(), "HTML Injection", 134217728, severity, "Certain", None, None, textIssue1, None, [attack], attack.getHttpService())]
        """
        textIssue2 = ""
        textIssue3 = ""
        tags = ""
        s2 = 0
        f2 = 0
        c = 0
        #reqinfo = burp_helpers.analyzeResponse(attack.getResponse())
        reqinfo = burp_helpers.analyzeRequest(baseRequestResponse)
        url = str(reqinfo.getUrl())
        #url = urlparse(url)
        dirtest = burp_helpers.buildHttpRequest(URL(url))
        attack1 = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),dirtest)
        response1 = attack1.getResponse()
        response_str1 = burp_helpers.bytesToString(response1)
        #if re.search(r'/((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*["\'\]]*\s*\()/', response_str1) is not None:
        if re.search('document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage', response_str1) is not None:
           s2 = 1
           f2 = 1
           textIssue2 = textIssue2 + "<br><br>VUlnerable Sinks<br>"
           severity = "High"
        x = re.search('(window\.\w+)(\s.*)(\|\|)', response_str1)   
        if x is not None:
           c = 1
           textIssue3 = textIssue3 + "<br><br>Clobbering may happen found potential global object with logical or Operator<br>"  + x.group(1)
           severity = "High"  
        if f2 == 1:
           if c == 1:
            return [CustomScanIssue(burp_helpers.analyzeRequest(attack1).getUrl(), "clobbering may happen",134217728, severity, "Certain", None, None, textIssue3, None, [attack1], attack1.getHttpService())]
           else:
            return [CustomScanIssue(burp_helpers.analyzeRequest(attack1).getUrl(), "Vulnerable Sinks are there",134217728, severity, "Certain", None, None, textIssue2, None, [attack1], attack1.getHttpService())]

        """
        c = 0
        textIssue3 = ""
        reqinfo1 = burp_helpers.analyzeRequest(baseRequestResponse)
        url1 = str(reqinfo1.getUrl())
        dirtest1 = burp_helpers.buildHttpRequest(URL(url1))
        attack2 = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),dirtest1)
        response2 = attack2.getResponse()
        response_str2 = burp_helpers.bytesToString(response2)
        if re.search('window\.(onload)', response_str2) is not None:
           c = 1
        if c == 1: severity = "High"
        if c == 1:
            textIssue3 = textIssue3 + "<br><br>Clobbering may be Possible <br>"
        if c == 1:    
            return [CustomScanIssue(burp_helpers.analyzeRequest(attack2).getUrl(), "Clobbering may be possible",134217728, severity, "Certain", None, None, textIssue3, None, [attack2], attack2.getHttpService())]
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0  
"""
    def doPassiveScan(self, baseRequestResponse):
        pass

    def println(self, message):
        self.stdout.println(message)

    def randstring(n):
        a = string.ascii_letters + string.digits
        return ''.join([random.choice(a) for i in range(n)])


class CustomScanIssue(IScanIssue):
    def __init__(self, Url, IssueName, IssueType, Severity, Confidence, IssueBackground,
                 RemediationBackground, IssueDetail, RemediationDetail, HttpMessages, HttpService):
        self._Url = Url
        self._IssueName = IssueName
        self._IssueType = IssueType
        self._Severity = Severity
        self._Confidence = Confidence
        self._IssueBackground = IssueBackground
        self._RemediationBackground = RemediationBackground
        self._IssueDetail = IssueDetail
        self._RemediationDetail = RemediationDetail
        self._HttpMessages = HttpMessages
        self._HttpService = HttpService

    def getUrl(self):
        return self._Url

    def getIssueName(self):
        return self._IssueName

    def getIssueType(self):
        return self._IssueType

    def getSeverity(self):
        return self._Severity

    def getConfidence(self):
        return self._Confidence

    def getIssueBackground(self):
        return self._IssueBackground

    def getRemediationBackground(self):
        return self._RemediationBackground

    def getIssueDetail(self):
        return self._IssueDetail

    def getRemediationDetail(self):
        return self._RemediationDetail

    def getHttpMessages(self):
        return self._HttpMessages

    def getHttpService(self):
        return self._HttpService