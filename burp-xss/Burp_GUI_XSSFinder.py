#!/usr/bin/env python
# coding:utf-8
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import re


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Xss logger")
        self._log = ArrayList()
        self._lock = Lock()
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self._POCURLViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        tabs.addTab("XSS_FUZZ_Param", self._POCURLViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        return

    def getTabCaption(self):
        return "Logger"

    def getUiComponent(self):
        return self._splitpane

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or ".css" in self._helpers.analyzeRequest(messageInfo).getUrl().toString():
            return
        analyIRequestInfo = self._helpers.analyzeRequest(messageInfo)
        headers = analyIRequestInfo.getHeaders()
        URL = re.findall(r"[GET|POST]\s(.*) HTTP\/", str(headers[0]))[0]
        analyzedResponse = self._helpers.analyzeResponse(messageInfo.getResponse())
        statusCode = analyzedResponse.getStatusCode()
        if statusCode == 200:
            resp = messageInfo.getResponse()
            body = resp[analyzedResponse.getBodyOffset():].tostring()
            result = re.findall('var(.*)=.*', body)
            resstr = ""
            for i in result:
                first_str = '='
                head, sep, tail = i.partition(first_str)
                resstr = resstr + '&' + str(head).replace(' ', '') + '=xxxxxx'
            POCURL = URL + "?" + resstr
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo),
                               self._helpers.analyzeRequest(messageInfo).getUrl(), POCURL))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "TOOL"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "FUZZ_PARAM"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        if columnIndex == 2:
            return logEntry._pocurl
        return ""

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._POCURLViewer.setMessage(logEntry._pocurl, True)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)


class LogEntry:
    def __init__(self, tool, requestResponse, url, POCURL):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._pocurl = POCURL
