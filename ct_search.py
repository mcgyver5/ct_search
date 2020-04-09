from java.net import URL
import requests
import os
from burp import IBurpExtender
from burp import ITab
from java.io import PrintWriter
from java.lang import RuntimeException
from burp import IContextMenuFactory
from javax.swing.table import TableColumnModel
from javax.swing.table import AbstractTableModel
from javax.swing import JFileChooser
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTable
from javax.swing import JMenuItem
from java.util import ArrayList
import json

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def	registerExtenderCallbacks(self, callbacks):

        # set our extension name
        callbacks.setExtensionName("Hello world extension")
        callbacks.registerContextMenuFactory(self)
        # obtain output stream
        self._stdout = PrintWriter(callbacks.getStdout(),True)
        stdout = PrintWriter(callbacks.getStdout(), True)

        # write a message to our output stream
        stdout.println("Hello World")
        self._stdout.println("Also, from object, Hello World")
        self._callbacks = callbacks

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts")

        #create and populate a jtable:
        initial_row = ['a','DOMAINS']
        self.fileTable = JTable(ResourceTableModel())
        # set up the Tab:

        self.infoPanel = JPanel()
        footerPanel = JPanel()

        footerPanel.add(JLabel("by mcgyver5 "))
        self._chooseFileButton = JButton("OPEN Local FILE", actionPerformed=self.fileButtonClick)
        self.infoPanel.add(JLabel("INFORMATION PANE"))

        self.infoPanel.add(self._chooseFileButton)
        scrollpane = JScrollPane(self.fileTable)
        ## this is a split inside the top component
        topPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        topPane.setTopComponent(self.infoPanel)
        topPane.setBottomComponent(scrollpane)
        self._chooseFileButton.setEnabled(True)
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setTopComponent(topPane)
        self._splitpane.setBottomComponent(footerPanel)
        #callbacks.addSuiteTab(self)

    def get_domains_from_json_list(self, json_list):
        my_domain_list = []
        for cert in json_list:
            try:
                domainList = str(cert.get('name_value')).strip()
                for domain in domainList.split("\n"):
                    if not domain in my_domain_list:
                        my_domain_list.append(domain)
            except Exception as e:
                print(e)
        my_domain_list.sort()
        return my_domain_list 
    
    def get_domains_from_api(self,domain):
        my_domain_list = []
        try:
            api_url = "https://crt.sh/?q=%.{}&output=json".format(domain)
            data = requests.get(api_url)
            json_list = json.loads(data.text)
            my_domain_list = self.get_domains_from_json_list(json_list)
        except Exception as e:
            print("error")
            print(e)
        return my_domain_list

    def lookup_ct(self, whatever):
        domain = ""
        http_traffic = self.context.getSelectedMessages()
        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            domain = host.replace('www.','')
            self._stdout.println(domain)
        domain_list = self.get_domains_from_api(domain)
        ct_tab = CTSearchTab(self._callbacks)
        self._callbacks.addSuiteTab(ct_tab)
        ct_tab.setDomainList(domain_list)


    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Lookup Domain in CT Logs", actionPerformed=self.lookup_ct))

        return menu_list
    def get_domains_from_file(self,file_data):
        json_list = json.loads(file_data)
        my_domain_list = []
        for cert in json_list:
            try:
                domainList = str(cert.get('name_value')).strip()
                for domain in domainList.split("\n"):
                    self._stdout.println(domain)
                    if not domain in my_domain_list:
                        my_domain_list.append(domain)
            except Exception as e:
                self._stdout.println(e)
        my_domain_list.sort()

        return my_domain_list

    def populateTableModel(self,f):
        domain_list = []
        num = 0
        try:
            path = os.getcwd()
            self._stdout.println("path is : " + path)

            fhandle = open(f) 
            file_data = fhandle.read()
            domain_list = self.get_domains_from_file(file_data)
            tableModel = self.fileTable.getModel()
        except Exception as e:
            self._stdout.println("exception!  ")
            self._stdout.println(e)
        for dom in domain_list:
            num = num + 1
            row = [dom,str(num)]
            tableModel.addRow(row)

    def fileButtonClick(self,callbacks):
        fileTypeList = ["csv","txt","json"]
        fileChooser = JFileChooser()
        result = fileChooser.showOpenDialog(self._splitpane)
        if result == JFileChooser.APPROVE_OPTION:
            f = fileChooser.getSelectedFile()
            fileName = f.getPath()
            self._stdout.println(fileName)

            self.populateTableModel(fileName)

    ## Implement ITab:
    def getTabCaption(self):
        return "Import URLs"
    
    def getUiComponent(self):
        return self._splitpane

class CTSearchTab(ITab):

    # constructor:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(),True)
        self._stdout.println("What are we doing in the object down here")
    # Implement ITab:
    
    def addToScope(self,whatever):
        self._stdout.println("add to scope called")
        self._stdout.println(whatever)
        for domain in self.domain_list:
            domain = domain.replace("*.","")
            url1 = URL("https://{}/".format(domain))
            if not self.callbacks.isInScope(url1):            
                self.callbacks.includeInScope(url1)

    def getTabCaption(self ):
        return "CT Search "

    def getUiComponent(self):
        self.domainTable = JTable(ResourceTableModel())
        self.domainTable.setRowHeight(30)
        columnModel = self.domainTable.getColumnModel()
        columnModel.getColumn(0).setPreferredWidth(40)
        columnModel.getColumn(1).setPreferredWidth(180)

        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        topPane = JPanel()
        
        b = JButton("Add Domains To Scope", actionPerformed=self.addToScope)
        topPane.add(b) 
        scrollpane = JScrollPane(self.domainTable)
        splitpane.setTopComponent(topPane)
        splitpane.setBottomComponent(scrollpane)
        return splitpane

    def setDomainList(self,domain_list):
        self.domain_list = domain_list
        tableModel = self.domainTable.getModel()
        n = 0
        for d in domain_list:
            row = [d,str(n)]
            tableModel.addRow(row)
            n = n + 1

class ResourceTableModel(AbstractTableModel):

    COLUMN_NAMES = ('num','domain')

    def __init__(self, *rows):
        self.data = list(rows)

    def getRowCount(self):
        return len(self.data)

    def getValueAt(self, rowIndex, columnIndex):
        row_values = self.data[rowIndex-1]
        return row_values[columnIndex -1]

    def hello_table_model(self):
        return "hello table model"

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getColumnName(self, columnIndex):
        return self.COLUMN_NAMES[columnIndex]

    def addRow(self, row=None):
        self.data.append(row)
        self.fireTableRowsInserted(len(self.data) -1, len(self.data )-1)
