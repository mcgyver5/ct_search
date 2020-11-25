from java.net import URL
import urllib2
import os
#import dns.resolver
from java.net import InetAddress
from java.net import UnknownHostException
from java.lang import Boolean
from java import io
from burp import IBurpExtender
from burp import ITab
from java.io import PrintWriter
from java.lang import RuntimeException
from java.lang import Exception
from burp import IContextMenuFactory
from javax.swing.table import TableColumnModel
from javax.swing.table import AbstractTableModel
from javax.swing import JFileChooser
from javax.swing import ImageIcon
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTable
from javax.swing import JMenuItem
from javax.swing import JFileChooser
from java.awt.event import MouseAdapter
from java.util import ArrayList
from javax import imageio
import json

DOMAIN_COLUMN = 1
CHECK_COLUMN = 3
DNS_COLUMN = 2

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def	registerExtenderCallbacks(self, callbacks):

        # set our extension name
        callbacks.setExtensionName("CT Search")
        callbacks.registerContextMenuFactory(self)
        # obtain output stream
        self._stdout = PrintWriter(callbacks.getStdout(),True)
        stdout = PrintWriter(callbacks.getStdout(), True)

        # write a message to our output stream
        self._callbacks = callbacks

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Hello alerts")

        #create and populate a jtable:
        initial_row = ['a','DOMAINS',True]
        self.fileTable = JTable(ResourceTableModel())
        # set up the Tab:

        self.infoPanel = JPanel()
        footerPanel = JPanel()

        footerPanel.add(JLabel("by mcgyver5 "))
#        self._chooseFileButton = JButton("OPEN Local FILE", actionPerformed=self.fileButtonClick)
        self.infoPanel.add(JLabel("INFORMATION PANE"))

#        self.infoPanel.add(self._chooseFileButton)
        scrollpane = JScrollPane(self.fileTable)
        ## this is a split inside the top component
        topPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        topPane.setTopComponent(self.infoPanel)
        topPane.setBottomComponent(scrollpane)
        #self._chooseFileButton.setEnabled(True)
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
        return list(set(my_domain_list)) 
    
    def get_domains_from_api(self,domain):
        my_domain_list = []
        try:
            api_url = "https://crt.sh/?q=%.{}&output=json".format(domain)
            request = urllib2.urlopen(api_url)
            data = request.read()
            json_list = json.loads(data)
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

    def fake_lookup_ct(self, whatever):
        domain_list = self.get_domains_from_file()
        ct_tab = CTSearchTab(self._callbacks)
        self._callbacks.addSuiteTab(ct_tab)
        ct_tab.setDomainList(domain_list)

    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Lookup Domain in CT Logs", actionPerformed=self.lookup_ct))
        menu_list.add(JMenuItem("CT LOgs Test get Domains from test file", actionPerformed=self.fake_lookup_ct))
        return menu_list

    def get_domains_from_file(self):
        my_domain_list = []
        fileChooser = JFileChooser()
        result = fileChooser.showOpenDialog(self._splitpane)
        if result == JFileChooser.APPROVE_OPTION:
            f = fileChooser.getSelectedFile()
            fileName = f.getPath()
            self._stdout.println(fileName)
            file_data = open(fileName).read()
            json_list = json.loads(file_data)
            for cert in json_list:
                try:
                    domainList = str(cert.get('name_value')).strip()
                    for domain in domainList.split("\n"):
                        if not domain in my_domain_list:
                            domain = domain.replace("*.","")
                            my_domain_list.append(domain)
                except Exception as e:
                    self._stdout.println(e)
            my_domain_list.sort()

        return list(set(my_domain_list))

#    def populateTableModel(self,f):
#        domain_list = []
#        num = 0
#        try:
#            path = os.getcwd()
#            self._stdout.println("path is : " + path)
#            fhandle = open(f) 
#            file_data = fhandle.read()
#            domain_list = self.get_domains_from_file(file_data)
#            tableModel = self.fileTable.getModel()
#        except Exception as e:
#            self._stdout.println("exception!  ")
#            self._stdout.println(e)
#        for dom in domain_list:
#            num = num + 1
#            row = [str(num),dom,False]
#            tableModel.addRow(row)
#
    def getTabCaption(self):
        return "Import URLs"
    
    def getUiComponent(self):
        return self._splitpane

class CTSearchTab(ITab):
    # constructor:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(),True)

    # Implement ITab:
    def saveResults(self, e):
        self._stdout.println("Saving results") 
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("Specify the file name")
        userSelection = fileChooser.showSaveDialog(self.getUiComponent())
        if userSelection == JFileChooser.APPROVE_OPTION:
            f = fileChooser.getSelectedFile()
            fileout = open(f,'w')
            for domain in self.domain_list:
                self._stdout.println("writing ") 
                fileout.write("I AM FILE")
            fileout.close()

    def addToScope(self,whatever):
        self._stdout.println("add to scope called")
        rowCount = self.domainTable.getRowCount()
        for row in range(0,rowCount):
            if self.domainTable.getValueAt(row,CHECK_COLUMN) == True:
                domain = self.domainTable.getValueAt(row,DOMAIN_COLUMN)
                domain = domain.replace("*.", "")
                url1 = URL("https://{}/".format(domain))
                if not self.callbacks.isInScope(url1):
                    self.callbacks.includeInScoe(url1)
    def check_address(self, addrblobs):
        for addrblob in addrblobs:
            addr_arr = addrblob.split("|")
            rrow = int(addr_arr[0])
            addr = addr_arr[1]
            try:
                result = InetAddress.getByName(addr)
                yield [rrow,"Success",result]
            except UnknownHostException:
                yield [rrow,"Fail",None]      

    def resolveDns(self,event):
        rowCount = self.domainTable.getRowCount()
        dns_check_list = []
        for row in range(0,rowCount):
            if self.domainTable.getValueAt(row,CHECK_COLUMN) == True:
                domain = self.domainTable.getValueAt(row,DOMAIN_COLUMN)
                domain = domain.replace("*.","")
                domain_string = str(row) + "|" + domain
                dns_check_list.append(domain_string)

        dns_results = self.check_address(dns_check_list)
        for dns_result in dns_results:
            saved_row = dns_result[0]
            if dns_result[1] == "Success":
                self.domainTable.setValueAt("Resolved",saved_row,DNS_COLUMN) 
            else:
                self.domainTable.setValueAt("No DNS Record",saved_row,DNS_COLUMN)

    def getTabCaption(self ):
        return "CT Search "

    def getUiComponent(self):
        self.domainTable = JTable(ResourceTableModel())
        self.domainTable.setRowHeight(30)
        #Delete:
        #jcolumnModel = self.domainTable.getColumnModel()

        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        topPane = JPanel()
        image_label = HelpLabel(self.callbacks)
        image_label.setHelpIcon("nothing")
        image_label.addMouseListener(ScreenMouseListener(self.callbacks))
        scope_button = JButton("Add Selected Domains To Scope", actionPerformed=self.addToScope)
        dns_button = JButton("Resolve DNS", actionPerformed=self.resolveDns)
#        search_text = JTextField("")
        saveButton = JButton("Save results", actionPerformed=self.saveResults)
        topPane.add(image_label) 
        topPane.add(scope_button)
        topPane.add(dns_button)
        topPane.add(saveButton)
        scrollpane = JScrollPane(self.domainTable)
        splitpane.setTopComponent(topPane)
        splitpane.setBottomComponent(scrollpane)
        return splitpane

    def setDomainList(self,domain_list):
        self.domain_list = domain_list
        tableModel = self.domainTable.getModel()
        n = 0
        dns_ans = "Not Checked"
        for d in domain_list:
            row = [str(n),d,dns_ans,True]
            tableModel.addRow(row)
            n = n + 1

class HelpLabel(JLabel):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(),True)
    ## HelpLabel is a JLabel with added help functionality
    def setHelpText(self, helpText):
        self.helpText = helpText
    def setHelpType(self, helpType):
        self.helpType = helpType

    ## MAD!  set the icon here as well:

    def setHelpIcon(self, helpIcon):
        image_file_name = "C:/users/tmcguire/documents/ct_search/help.png"
        # it can only be a local file so helpIcon is a text string pointing to a local file
        self.setIcon(ImageIcon(image_file_name))
        # add mouse stuff later:
        # self.addMouseListener(ScreenMouseListener(self.callbacks))
class HelpSystem():
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(),True)
    
    def setText(self, helpText):
        self.helpText = helpText


class ScreenMouseListener(MouseAdapter):
        # constructor:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(),True)
        self._stdout.println("we are in this weird mouseListener, I think ")
    def mousePressed(self, event):
        self._stdout.println("Also, from mouse press")
    
    def mouseClicked(self, event):
        pass

    def mouseDragged(self, event):
        pass

    def mouseMoved(self,event):
        pass

    def mouseReleased(self, event):
        pass

    def mouseWheelMoved(self,event):
        pass
    
    def mouseEntered(self, event):
        pass

    def mouseExited(self,event):
        pass
    
    

class ResourceTableModel(AbstractTableModel):

    COLUMN_NAMES = ('num','domain','DNS Resolve','selected')

    def __init__(self, *rows):
        self.data = list(rows)

    def getRowCount(self):
        return len(self.data)

    def getValueAt(self, rowIndex, columnIndex):
        row_values = self.data[rowIndex]
        return row_values[columnIndex]

    def setValueAt(self, value, rowIndex, columnIndex):
        if columnIndex == CHECK_COLUMN:
            row_values = self.data[rowIndex]
            row_values[columnIndex] = value
            self.fireTableCellUpdated(rowIndex, columnIndex)
        if columnIndex == DNS_COLUMN:
            row_values = self.data[rowIndex]
            row_values[columnIndex] = value
            self.fireTableCellUpdated(rowIndex,columnIndex)

    def hello_table_model(self):
        return "hello table model"

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getColumnName(self, columnIndex):
        return self.COLUMN_NAMES[columnIndex]

    def addRow(self, row=None):
        self.data.append(row)
        self.fireTableRowsInserted(len(self.data) , len(self.data ))
    
    def isCellEditable(self, rowIndex, columnIndex):
        return columnIndex == CHECK_COLUMN 

    def getColumnClass(self, columnIndex):
        if columnIndex == CHECK_COLUMN:
            return Boolean
        else: 
            return str
