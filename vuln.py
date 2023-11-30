from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import random

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RCE-Finder")

        # Register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def doPassiveScan(self, baseRequestResponse):
        # Example: Enhance sensitivity by looking for common indicators of RCE
        matches = self._get_matches(baseRequestResponse.getResponse(), b"eval(")
        if not matches:
            return None

        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
            "RCE Finder - Potential Issue",
            "The response contains potential indicators of Remote Code Execution (RCE). Further analysis is recommended.",
            "High"
        )]

    def doActiveScan(self, baseRequestResponse, insertionPoint):
    # Example: Inject different payloads for active scanning
    payloads = [
        b"';alert('XSS');//",
        b"$(document).ready(function(){alert('XSS')});",
        b'"><s>xss',
        b'"><A HRef=\" AutoFocus OnFocus=top/**/?.[\'ale\'%2B\'rt\'](1)>',
        b'\u0022\u003c%26quot;%26gt;%26lt;"\';}};</SCRIPT><img src=x onerror=alert(69)>${{7*7}}',
        # Add your additional payloads here
    ]

    for payload in payloads:
        checkRequest = insertionPoint.buildRequest(payload)
        checkRequestResponse = self._callbacks.makeHttpRequest(
            baseRequestResponse.getHttpService(), checkRequest)

        # Example: Check for specific error messages indicating a vulnerability
        matches = self._get_matches(checkRequestResponse.getResponse(), b"error")
        if matches:
            requestHighlights = [insertionPoint.getPayloadOffsets(payload)]
            return [CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches)],
                "Potential Injection Vulnerability",
                "The application may be vulnerable to injection attacks. Verify and remediate.",
                "High"
            )]

    return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
