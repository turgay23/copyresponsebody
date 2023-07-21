# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JOptionPane
import threading
import time


class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):

    def __init__(self):
        self.clipboard_lock = threading.Lock()

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Copy Response Body")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        self.helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        callbacks.registerContextMenuFactory(self)

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()

        menuList.add(JMenuItem("Copy Response Body", actionPerformed=self.copyResponseBody))

        return menuList

    def copyResponseBody(self, event):
        httpTraffic = self.context.getSelectedMessages()[0]
        httpResponse = httpTraffic.getResponse()
        httpResponseBodyOffset = self.helpers.analyzeResponse(httpResponse).getBodyOffset()

        data = httpResponse[httpResponseBodyOffset:]
        data.append(13)
        print(type(data))
        data = data.tostring()

        # Ugly hack because VMware is messing up the clipboard if a text is still selected, the function
        # has to be run in a separate thread which sleeps for 1.5 seconds.
        t = threading.Thread(target=self.copyToClipboard, args=(data, True))
        t.start()

    def copyToClipboard(self, data, sleep=False):
        if sleep is True:
            time.sleep(1.5)

        # Fix line endings of the headers
        data = self.helpers.bytesToString(data).replace('\r\n', '\n')

        with self.clipboard_lock:
            systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            systemSelection = Toolkit.getDefaultToolkit().getSystemSelection()
            transferText = StringSelection(data)
            systemClipboard.setContents(transferText, None)
            systemSelection.setContents(transferText, None)
