from burp import IBurpExtender
from java.io import PrintWriter
from java.lang import RuntimeException

class BurpExtender(IBurpExtender):
    
    def	registerExtenderCallbacks(self, callbacks):
        stdout = PrintWriter(callbacks.getStdout(), True)
        stdout.println("Hello World!")
        callbacks.issueAlert("Hello World Alert")
