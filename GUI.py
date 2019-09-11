import string
import binascii
from PyQt5 import QtCore, QtGui, QtWidgets

class VirtuailorBasicGUI(QtWidgets.QDialog):
    values_cb = None
    start_line = None
    stop_line = None
    base_line = None

    def populate_form(self, defaults):
        layout = QtWidgets.QVBoxLayout() # TODO implement exit()
        layout.addWidget(QtWidgets.QLabel("Virtuailor- \n\n Please Choose Address range (in hex)"))
        layout.addWidget(QtWidgets.QLabel("\n In case you would like to target all the binary, just leave the "
                                          "addresses in both start and end fields. \n "))

        start_label = QtWidgets.QLabel()
        start_label.setText("Start Address:")
        layout.addWidget(start_label)

        self.start_line = QtWidgets.QLineEdit()
        self.start_line.setObjectName("start_line")
        self.start_line.setText(str(defaults['start']))
        layout.addWidget(self.start_line)

        stop_label = QtWidgets.QLabel()
        stop_label.setText("End Address:")
        layout.addWidget(stop_label)

        self.stop_line = QtWidgets.QLineEdit()
        self.stop_line.setObjectName("stop_line")
        self.stop_line.setText(str(defaults['end']))
        layout.addWidget(self.stop_line)

        button_ok = QtWidgets.QPushButton('&OK')
        button_ok.setDefault(True)
        button_ok.clicked.connect(self.on_button_clicked)
        layout.addWidget(button_ok)

        button_cancel = QtWidgets.QPushButton('&Cancel')
        button_cancel.setDefault(True)
        button_cancel.clicked.connect(self.on_button_clicked_cancel)
        layout.addWidget(button_cancel)

        self.setLayout(layout)

    def __init__(self, cb, defaults):
        self.values_cb = cb
        QtWidgets.QDialog.__init__(self, None, QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowTitleHint)
        self.populate_form(defaults)

    def on_button_clicked(self):
        start = int(self.start_line.text(), 16)
        end = int(self.stop_line.text(), 16)

        self.values_cb(start, end)
        self.close()

    def on_button_clicked_cancel(self):
        self.start_line.text = "banana"
        self.close()

