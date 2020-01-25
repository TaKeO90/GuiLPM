#!/usr/bin/python3

###### PASSWORD MANAGER GUI APP ###### 						##### author yassine messaoudi aka TAKEO ##### 


from symmetric import Crypt
from passgenerator import PassGen
#############################
from PyQt5.QtWidgets import *
from PyQt5.QtGui import * 
from PyQt5.QtCore import *
from PyQt5 import QtCore, QtGui
from PyQt5.uic import loadUi
import sys , sqlite3 , hashlib , shutil ,re ,os, pyperclip



#Todo Create a TAB for generating secure passwords

## Main Menu Window ## 

class Menu(QWidget):

	def __init__(self):
		super().__init__()
		self.title = "Password Manager"	
		self.width = 800
		self.height= 600
		self.ReturnButton_Width  = 50 
		self.ReturnButton_length = 30
		self.CenterLabel_left = 60
		self.CenterLabel_Down = 237
		self.EntryLeftPosition = 220 
		self.userDB_folder = "./main_cred_db"
		self.initUI()

	#def closeEvent(self,*args,**kwargs):
		#super(Menu,self).closeEvent(*args,**kwargs)
		#print("window Closed")


	def initUI(self):
		self.setWindowTitle(self.title)
		self.setFixedSize(self.width,self.height)
		self.setStyleSheet("background-color:#031426")
		label = QLabel(self)
		label.move(155,50)
		text = "PASSWORD MANAGER"


		label.setText(text)
		#label.setAlignment(QtCore.Qt.AlignCenter)
		label.setStyleSheet("color:purple")

		font = QFont("Times",34,QFont.Bold)
		label.setFont(font)

		b0 = QPushButton("REGISTER",self)
		#b0.setGeometry(300,250,150,80)
		b0.clicked.connect(self.registerclicked)

		b1 = QPushButton("LOGIN",self)
		#b1.setGeometry(300,270,150,80)
		b1.clicked.connect(self.loginclicked)
		

		# Create a layout 
		grid = QGridLayout()
		grid.addWidget(label, 0,2,alignment=Qt.AlignTop|Qt.AlignCenter)
		grid.addWidget(b0, 1,2 , alignment=Qt.AlignTop|Qt.AlignCenter)
		grid.addWidget(b1, 2,2, alignment=Qt.AlignTop|Qt.AlignCenter)

		self.setLayout(grid)

		self.show()

	@pyqtSlot()
	def registerclicked(self):
		self.screen = Register()
		self.screen.show()
		self.close()

	@pyqtSlot()
	def loginclicked(self):
		self.screen = Login()
		self.screen.show()
		self.close()

class Register(QWidget):

	def __init__(self):
		super().__init__()
		m = Menu()
		self.setWindowTitle(m.title)
		self.setFixedSize(m.width,m.height)
		self.setStyleSheet("background-color:#031426")
		self.C = Crypt()

		#Button to get back to main menu Screen 
		b = QPushButton("Return",self)
		#b.setGeometry(0,0,m.ReturnButton_Width,m.ReturnButton_length)
		b.clicked.connect(self.returnclicked)

		#Label to indicate that this page is for registration 
		R = QLabel(self)
		R.setText("REGISTER")
		#R.setGeometry(300,70,250,150)
		R.setStyleSheet("font:29pt;color:purple")
		font = QFont("Times",34,QFont.Bold)
		R.setFont(font)


		#Label for indicating that we need a username from the user
		l = QLabel(self)
		l.setText("Username: ")
		#l.setGeometry(m.CenterLabel_left,m.CenterLabel_Down,95,80)
		l.setStyleSheet("font:11pt;color:purple")

		#Label for password field 
		l0 = QLabel(self)
		#l0.setGeometry(m.CenterLabel_left,(m.CenterLabel_Down+60),95,50)
		l0.setText("Password: ")
		l0.setStyleSheet("font:11pt;color:purple")

		#Label for email field
		email = QLabel(self)
		email.setText("Email: ")
		email.setStyleSheet("font:11pt;color:purple")
		#email.setGeometry(m.CenterLabel_left,(m.CenterLabel_Down+120),95,50)

		#Form to get the username
		self.username_field = QLineEdit("",self)
		self.username_field.setStyleSheet("font:11pt;background-color:white;color:black")
		#self.username_field.setGeometry(m.EntryLeftPosition,(m.CenterLabel_Down+15),270,40)

		#Form to get the password 
		self.password = QLineEdit(self)
		self.password.setEchoMode(QLineEdit.Password)
		#self.password.setGeometry(m.EntryLeftPosition,(m.CenterLabel_Down+69),270,40)
		self.password.setStyleSheet("color:black;background-color:white")

		#Form to get email 
		self.email = QLineEdit("",self)
		self.email.setStyleSheet("font:11pt;color:black;background-color:white")
		#self.email.setGeometry(m.EntryLeftPosition,(m.CenterLabel_Down+129),270,40)

		#Submit Button 
		b0 = QPushButton("Register",self)
		#b0.setGeometry((m.EntryLeftPosition+310),(m.CenterLabel_Down+180),100,60)
		b0.clicked.connect(self.get_register)

		#Bind return key with registeration fuction

		self.username_field.returnPressed.connect(self.get_register)
		self.email.returnPressed.connect(self.get_register)
		self.password.returnPressed.connect(self.get_register)


		#Create a Label for showing messages
		self.succ_l = QLabel(self)
		#self.succ_l.setGeometry(220,(m.CenterLabel_Down+180),300,310)
		self.succ_l.setStyleSheet('color:green')

		# Add grid layout 
		grid = QGridLayout()
		grid.addWidget(b,0,0,alignment=Qt.AlignTop|Qt.AlignLeft) #return button
		grid.addWidget(R,0,2,alignment=Qt.AlignTop|Qt.AlignCenter) #Rgister Label
		grid.addWidget(l,2,0,alignment=Qt.AlignTop|Qt.AlignLeft) #username label
		grid.addWidget(self.username_field,2,2,alignment=Qt.AlignTop|Qt.AlignCenter) #username qlineedit
		grid.addWidget(l0,3,0,alignment=Qt.AlignTop|Qt.AlignLeft) # password label
		grid.addWidget(self.password,3,2,alignment=Qt.AlignTop|Qt.AlignCenter) # password qlineedit
		grid.addWidget(email,4,0,alignment=Qt.AlignTop|Qt.AlignLeft) #email label 
		grid.addWidget(self.email,4,2,alignment=Qt.AlignTop|Qt.AlignCenter) # email qliteedit
		grid.addWidget(b0,6,3,alignment=Qt.AlignTop|Qt.AlignRight) #Register button 
		grid.addWidget(self.succ_l,7,2,alignment=Qt.AlignTop|Qt.AlignCenter) # messages 

		self.setLayout(grid)




	#def get_user(self,username):
		#self.cursor.execute("SELECT USERNAME FROM users WHERE USERNAME = '%s' "%(username))
		#queryuser = self.cursor.fetchone()
		#if queryuser is not None : 
			#return queryuser[0]
		#else : 
			#return []

	#def get_email(self,email):
		#self.cursor.execute("SELECT EMAIL FROM users WHERE EMAIL='%s' " %(email))
		#queryemail = self.cursor.fetchone()
		#if queryemail is not None :
			#return queryemail[0]
		#else : 
			#return []
	
	def registration_process(self):
		# TODO Create for each New User a separate Main creds db Where the Master password is stored

		# Hashing the password with SHA256
		password_H = hashlib.sha256(bytes(self.password_reg,('utf-8')))
		password_Hx = password_H.hexdigest()

		#Create Master password db for the user 
		Mp_db = shutil.copy2("User.db",f"User{self.username}.db")
		#Create Credential db for the user
		db_path = shutil.copy2("defaulcred.db",f"./main_cred_db/{self.username}.db")

		#Generate a Symmetric key
		keys_Path = './keys'
		self.C.generate_key(keys_Path,self.username)

		#Load that symmetric key and encrypt the Db
		key = self.C.load_key(keys_Path,self.username)

		#Encrypt the db
		self.C.encrypt(db_path,key)

		MPD = f"User{self.username}.db"

		#connect to the MAster password db 
		self.conn = sqlite3.connect(MPD)
		self.cursor = self.conn.cursor()

		# Store Main Credentials
		self.cursor.execute("INSERT INTO users (USERNAME,PASSWORD,EMAIL,DBPATH) \
			VALUES('%s','%s','%s','%s');" %(self.username,password_Hx,self.email_reg,db_path))
		self.conn.commit()

		#Encrypt the MPD 
		self.C.encrypt(MPD,key)

		self.succ_l.setText("successfully Registred and generated your symmetric key")


	def get_register(self):

		#get username ,password and email from the QLineEdit
		self.username = self.username_field.text()
		self.password_reg = self.password.text()
		self.email_reg    = self.email.text()

		#Check For the email if it's valid or not 
		reg = re.findall(r'\S+@\S+',self.email_reg)
	
		if self.username == "" or self.password_reg == "" or self.email_reg == "":
			self.succ_l.setText("You haven't complete the registration fields !")

		elif not reg :
			self.succ_l.setText("Email Not Valid!!")

		else : 
			self.registration_process()

	@pyqtSlot() # Return to the Main menu screen 
	def returnclicked(self):
		self.screen = Menu()
		self.screen.show()
		self.close()



class Login(QWidget):

	NEW_KEY_PATH = []	

	def __init__(self):
		super().__init__()
		m = Menu()
		self.setWindowTitle(m.title)
		self.setFixedSize(m.width,m.height)
		self.setStyleSheet("background-color:#031426")
		self.C = Crypt()
		self.session_folder = "./session"
		
		loglabel=QLabel(self)
		loglabel.setText("LOGIN")
		loglabel.setStyleSheet("font:29pt;color:purple")
		font = QFont("Times",34,QFont.Bold)
		loglabel.setFont(font)

		b = QPushButton("return")
		b.clicked.connect(self.returnclicked)

		
		user = QLabel(self)
		user.setText("Username:")
		user.setStyleSheet("font:11pt;color:purple")

		passwd = QLabel(self)
		passwd.setText("Password:")
		passwd.setStyleSheet("font:11pt;color:purple")

		Kkey = QLabel(self)
		Kkey.setText("Key Path:(*Optional)")
		Kkey.setStyleSheet("font:11pt;color:purple")


		self.username_lg = QLineEdit(self)
		self.username_lg.setStyleSheet("font:11pt;background-color:white;color:black")
		self.username_lg.returnPressed.connect(self.get_loggedin)

		self.password_lg = QLineEdit(self)
		self.password_lg.setEchoMode(QLineEdit.Password)
		self.password_lg.setStyleSheet("font:11pt;background-color:white;color:black")
		self.password_lg.returnPressed.connect(self.get_loggedin)

		BrButton = QPushButton("Browse",self)
		BrButton.clicked.connect(self.BrowseFiles)


		
		self.message = QLabel(self)
		self.message.setStyleSheet("color:green")


		
		loginButton = QPushButton("Login",self)
		loginButton.clicked.connect(self.get_loggedin)

		grid = QGridLayout()
		grid.addWidget(b,0,0,alignment=Qt.AlignLeft)
		grid.addWidget(loglabel,1,1,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(user,2,0,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(self.username_lg,2,1,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(passwd,3,0,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(self.password_lg,3,1,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(Kkey,4,0,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(BrButton,4,1,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(loginButton,5,1,alignment=Qt.AlignTop|Qt.AlignLeft)
		grid.addWidget(self.message,6,1,alignment=Qt.AlignTop|Qt.AlignLeft)

		self.setLayout(grid)

	
	def BrowseFiles(self):
		self.Kkey_lg , _ = QFileDialog.getOpenFileName(self)


	def get_loggedin(self):
		#Get the username and password
		self.user = self.username_lg.text()
		self.passwd = self.password_lg.text()
		self.passwdH = hashlib.sha256(bytes(self.passwd,("utf-8")))
		self.passwdHx = self.passwdH.hexdigest()
		

		MPD = f"User{self.user}.db"
		EMPD = MPD+".encrypted"
		
		try :
			self.key_path = self.Kkey_lg.strip(f"{self.user}.key")
			self.NEW_KEY_PATH.append(self.key_path)
			print(self.key_path)
		except AttributeError :
			self.key_path = "./keys"
			self.NEW_KEY_PATH.append(self.key_path)
		
		try : 
			#load the symmetric key to decrypt the user db
			self.key = self.C.load_key(self.key_path,self.user)
			self.C.decrypt(EMPD,MPD,self.key)
			self.message.setText("no such user found")
			self.conn = sqlite3.connect(MPD)
			self.cursor = self.conn.cursor()

			self.cursor.execute("SELECT USERNAME , PASSWORD  FROM users WHERE USERNAME = ? AND PASSWORD = ? ",(self.user,self.passwdHx))

			if self.cursor.fetchone() is not None :
				#create session file
				user_session_file = os.path.join(self.session_folder,self.user) 
				open(user_session_file,"a").close()
				#decrypt the db 
				self.db = f"./main_cred_db/{self.user}.db.encrypted"
				self.endfile = f"./main_cred_db/{self.user}.db"
				self.C.decrypt(self.db,self.endfile,self.key)

				self.goToCreds() # Show credential tables 

			else : 
				self.message.setText("Wrong username/password !!")

		except Exception as e :
			self.message.setText("No such user or keypath is incorrect")
			


	@pyqtSlot()
	def returnclicked(self):
		self.screen = Menu()
		self.screen.show()
		self.close()

	@pyqtSlot()
	def goToCreds(self):
		self.screen = Credentials()
		self.screen.show()
		self.close()

class Credentials(QWidget):
	def __init__(self):
		super().__init__()
		m = Menu()
		self.p = PassGen()
		self.l = Login()
		self.setWindowTitle(m.title)
		self.setFixedSize(m.width,m.height)
		self.setStyleSheet("background-color:#031426")
		self.layout = QVBoxLayout(self)
		self.rows = 25
		#create another connection to user creds 
		self.Udb = m.userDB_folder
		self.s = Session()
		self.user_database_path = os.path.join(self.Udb,f"{self.s.get_current_user()}.db")
		
		self.cnx = sqlite3.connect(self.user_database_path)
		self.c = self.cnx.cursor()


		#Qtabs here 
		self.tabs = QTabWidget() #Main tab 
		# 1st tab is for inserting credentials into user db
		#self.tab1 = QWidget()
		# 2nd tab for showing social sites creds
		self.tab2 = QWidget()
		# 3rd tab for showing email creds
		self.tab3 = QWidget()
		# 4th tab for showing finance sites creds
		self.tab4 = QWidget()
		# 5th tab for showing shopping sites creds
		self.tab5 = QWidget()
		# 6th tab for other creds
		self.tab6 = QWidget()
		# 7th tab for generating password 
		self.tab7 = QWidget()


		#self.tabs.addTab(self.tab1,"Save Your Credentials")
		self.tabs.addTab(self.tab2,"Social")
		self.tabs.addTab(self.tab3,"Email")
		self.tabs.addTab(self.tab4,"finance")
		self.tabs.addTab(self.tab5,"shopping")
		self.tabs.addTab(self.tab6,"Other")
		self.tabs.addTab(self.tab7,"Generate Password")


		self.show_creds() #this function show users credential in tables 

		self.tab7.layout = QGridLayout()
		self.slider = QSlider(Qt.Horizontal,self)
		self.slider.valueChanged[int].connect(self.changeValue)
		self.lengP = QLabel()
		self.lengP.setText("Password length")
		self.lengP.setStyleSheet("color:purple")

		self.showvalue = QLabel()
		self.showvalue.setStyleSheet("color:green")
		font = QFont("Times",14,QFont.Bold)
		self.showvalue.setFont(font)

		#Radio button to choose which type of passwords you wanna generate 
		#1st lower and upper case letter password "radio button, rdb"
		self.rdb = QRadioButton("UpperLower case Letters")
		self.rdb.setStyleSheet("color:purple")
		self.rdb.setChecked = False 
		self.rdb.toggled.connect(self.showGenPassrd)

		#2nd lower upper case letters and digits
		self.rdb0 = QRadioButton("Upper,Lower case ,digits")
		self.rdb0.setStyleSheet("color:purple")
		self.rdb0.setChecked= False
		self.rdb0.toggled.connect(self.showGenPassrd0)

		#3rd Complex passwrod 
		self.rdb1 = QRadioButton("Complex PW")
		self.rdb1.setStyleSheet("color:purple")
		self.rdb1.setChecked = False
		self.rdb1.toggled.connect(self.showGenPassrd1)

		self.pwd = QLineEdit()
		self.pwd.setStyleSheet("font:15pt;background-color:white;color:black")

		self.tab7.layout.addWidget(self.lengP,1,0,alignment=Qt.AlignLeft)
		self.tab7.layout.addWidget(self.slider,1,1,alignment=Qt.AlignCenter)
		self.tab7.layout.addWidget(self.showvalue,2,1,alignment=Qt.AlignCenter)
		self.tab7.layout.addWidget(self.rdb,4,0,alignment=Qt.AlignLeft)
		self.tab7.layout.addWidget(self.rdb0,4,1,alignment=Qt.AlignCenter)
		self.tab7.layout.addWidget(self.rdb1,4,2,alignment=Qt.AlignRight)
		self.tab7.layout.addWidget(self.pwd,5,1,alignment=Qt.AlignCenter)

		self.tab7.setLayout(self.tab7.layout)

		self.layout.addWidget(self.tabs)
		self.setLayout(self.layout)

	def errorNotify(self):
		msgBox = QMessageBox()
		msgBox.setIcon(QMessageBox.Information)
		msgBox.setText("You Didn't specify the length yet")
		msgBox.setWindowTitle("Info")
		msgBox.setStandardButtons(QMessageBox.Ok)
		returnValue = msgBox.exec()
		if returnValue == QMessageBox.Ok : 
			msgBox.close()


	def showGenPassrd(self):
		try : 
			radiobutton = self.sender()
			if radiobutton.isChecked():
				self.pwd.setText(self.rdb.type)
				pyperclip.copy(self.rdb.type)
		except AttributeError : 
			self.errorNotify()

	def showGenPassrd0(self):
		try :
			radiobutton = self.sender()
			if radiobutton.isChecked():
				self.pwd.setText(self.rdb0.type)
				pyperclip.copy(self.rdb0.type)
		except AttributeError:
			self.errorNotify()  #replace

	def showGenPassrd1(self):
		try : 
			radiobutton = self.sender()
			if radiobutton.isChecked():
				self.pwd.setText(self.rdb1.type)
				pyperclip.copy(self.rdb1.type)
		except AttributeError : 
			self.errorNotify()

	def changeValue(self,value): 
		self.showvalue.setText(str(value)) # Here We are going to create a variable where we can store the slider value to use it later in the generating password func 
		self.rdb.type = self.p.lowerupperPass(value) #function of generating the upper and lower case password
		self.rdb0.type = self.p.lowerUpperDigitPass(value)
		self.rdb1.type = self.p.complexPass(value)

	
	def show_creds(self): # Create table for each tab 
		self.tab2.layout = QVBoxLayout()
		data_tab2 = self.query_creds_process("social")
		#Button save creds for each tab 
		SV_b0 = QPushButton("Save")
		SV_b0.clicked.connect(self.getModifiedStuff)
		# First table for the first tab 
		self.social_table = QTableWidget()
		self.social_table.setStyleSheet("background-color:white;color:black")
		self.social_table.setRowCount(self.rows)
		self.social_table.setColumnCount(3)
		self.social_table.setHorizontalHeaderLabels(["Username","Password","Site"])
		header = self.social_table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		#add data into it 
		self.add_creds_to_table(data_tab2,self.social_table)
		self.tab2.layout.addWidget(self.social_table)
		self.tab2.layout.addWidget(SV_b0)
		self.tab2.setLayout(self.tab2.layout)


		self.tab3.layout = QVBoxLayout()
		data_tab3 = self.query_creds_process("email")
		#Button save creds for each tab 
		SV_b1 = QPushButton("Save")
		SV_b1.clicked.connect(self.getModifiedStuff)
		self.email_table = QTableWidget()
		self.email_table.setStyleSheet("background-color:white;color:black")
		self.email_table.setRowCount(self.rows)
		self.email_table.setColumnCount(3)
		self.email_table.setHorizontalHeaderLabels(["Username","Password","Site"])
		header = self.email_table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		self.tab3.layout.addWidget(self.email_table)
		self.tab3.layout.addWidget(SV_b1)
		self.add_creds_to_table(data_tab3,self.email_table)
		self.tab3.setLayout(self.tab3.layout)


		self.tab4.layout = QVBoxLayout()
		data_tab4 = self.query_creds_process("finance")
		#Button save creds for each tab 
		SV_b2 = QPushButton("Save")
		SV_b2.clicked.connect(self.getModifiedStuff)
		self.finance_table = QTableWidget()
		self.finance_table.setStyleSheet("background-color:white;color:black")
		self.finance_table.setRowCount(self.rows)
		self.finance_table.setColumnCount(3)
		self.finance_table.setHorizontalHeaderLabels(["Username","Password","Site"])
		header = self.finance_table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		self.tab4.layout.addWidget(self.finance_table)
		self.tab4.layout.addWidget(SV_b2)
		self.add_creds_to_table(data_tab4,self.finance_table)
		self.tab4.setLayout(self.tab4.layout)


		self.tab5.layout = QVBoxLayout()
		data_tab5 = self.query_creds_process("shopping")
		#Button save creds for each tab 
		SV_b3 = QPushButton("Save")
		SV_b3.clicked.connect(self.getModifiedStuff)
		self.shopping_table = QTableWidget()
		self.shopping_table.setStyleSheet("background-color:white;color:black")
		self.shopping_table.setRowCount(self.rows)
		self.shopping_table.setColumnCount(3)
		self.shopping_table.setHorizontalHeaderLabels(["Username","Password","Site"])
		header = self.shopping_table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		self.tab5.layout.addWidget(self.shopping_table)
		self.tab5.layout.addWidget(SV_b3)
		self.add_creds_to_table(data_tab5,self.shopping_table)
		self.tab5.setLayout(self.tab5.layout)


		self.tab6.layout = QVBoxLayout()
		data_tab6 = self.query_creds_process("other")
		#Button save creds for each tab
		SV_b4 = QPushButton("Save")
		SV_b4.clicked.connect(self.getModifiedStuff)
		self.other_table = QTableWidget()
		self.other_table.setStyleSheet("background-color:white;color:black")
		self.other_table.setRowCount(self.rows)
		self.other_table.setColumnCount(3)
		self.other_table.setHorizontalHeaderLabels(["Username","Password","Site"])
		header = self.other_table.horizontalHeader()
		header.setStretchLastSection(True)
		header.setSectionResizeMode(QHeaderView.Stretch)
		self.tab6.layout.addWidget(self.other_table)
		self.tab6.layout.addWidget(SV_b4)
		self.add_creds_to_table(data_tab6,self.other_table)
		self.tab6.setLayout(self.tab6.layout)

	
	def getModifiedStuff(self):
		self.tabsIndex = self.tabs.currentIndex()
		 
		if self.tabsIndex == 0 :
			self.table = "social"
			self.socialTableContent = self.grabTableContent(self.social_table)
			self.SaveModifedStuff(self.table,self.socialTableContent)
			self.messageConf()
		
			

		if self.tabsIndex == 1 :
			self.table = "email"
			self.emailTableContent = self.grabTableContent(self.email_table)
			self.SaveModifedStuff(self.table,self.emailTableContent)
			self.messageConf()
			
		if self.tabsIndex == 2 : 
			self.table = "finance"
			self.financeTableContent = self.grabTableContent(self.finance_table)
			self.SaveModifedStuff(self.table,self.financeTableContent)
			self.messageConf()

			
		if self.tabsIndex == 3 :
			self.table = "shopping"
			self.shoppingTableContent = self.grabTableContent(self.shopping_table)
			self.SaveModifedStuff(self.table,self.shoppingTableContent)
			self.messageConf()
			
		if self.tabsIndex == 4 : 
			self.table = "other"
			self.otherTableContent = self.grabTableContent(self.other_table)
			self.SaveModifedStuff(self.table,self.otherTableContent)
			self.messageConf()


	def SaveModifedStuff(self,tablename,table): # tablename = name of the table , table is data of the modified table 
		ttable = self.listToTuple(table)
		query = self.query_creds_process(tablename)
		if ttable != query :
			self.delete_DB_table(tablename)
			for x,y,z in ttable : 
				self.save_creds(tablename,x,y,z)


	def messageConf(self):
		#resultMessage = QMessageBox.question(self,"Message","Sucessfully saved your Data",QMessageBox.Ok)# Qmessage box here
		#if resultMessage == QMessageBox.Ok :
			#self.update_Window()
		msgBox = QMessageBox()
		msgBox.setIcon(QMessageBox.Information)
		msgBox.setText("successfully saved")
		msgBox.setWindowTitle("Info")
		msgBox.setStandardButtons(QMessageBox.Ok)
		returnValue = msgBox.exec()
		if returnValue == QMessageBox.Ok : 
			self.update_Window()


	def listToTuple(self,table):
		j = 0
		a = []
		for i in table :
			a.append(tuple(table[j:j+3]))
			j+=3
			if table[j:j+3] == []:
				break
		return a
		

	def delete_DB_table(self,tablename):
		self.c.execute("DELETE FROM '%s'"%(tablename))
		self.cnx.commit()


	@pyqtSlot()
	def update_Window(self):
		self.screen = Credentials()
		self.screen.show()
		self.close()

	def query_creds_process(self,tablename):
		# Query from user creds DB
		self.c.execute("SELECT user,pw,site FROM '%s' " %(tablename))
		data = self.c.fetchall()
		return data

	def add_creds_to_table(self,data,table):
		i = 0
		for u,p,s in data :
			table.setItem(i,0,QTableWidgetItem(u))
			table.setItem(i,1,QTableWidgetItem(p))
			table.setItem(i,2,QTableWidgetItem(s))
			i+=1

	
	def grabTableContent(self,table):
		rows = table.rowCount()
		columns = table.columnCount()
		r = []
		for i in range(rows):
			for j in range(columns):
				if table.item(i,j) is not None : 
					r.append(table.item(i,j).text())
		return r

	def save_creds(self,category,username,passwd,site):
		self.c.execute("INSERT INTO '%s' (user,pw,site) \
			VALUES ('%s','%s','%s');" %(category.lower().strip(),username,passwd,site))
		self.cnx.commit()

	
class Session:
	def get_current_user(self):
		username = os.listdir("./session")
		if len(username) > 0 :
			return username[0]


def appExec():
	app = app = QApplication(sys.argv)
	ex = Menu()
	s = Session()
	C = Crypt()
	L = Login()
	app.exec_()
	try : 
		# encrypting db
		key = C.load_key(L.NEW_KEY_PATH[0],s.get_current_user())
		C.encrypt(f"User{s.get_current_user()}.db",key)
		C.encrypt(f"./main_cred_db/{s.get_current_user()}.db",key)
		print("[+] Credential DATABASE encrypted !") 
		#Remove session file 
		path = os.path.join("./session",s.get_current_user())
		print("[+] Closing this session ==> ",s.get_current_user())
		os.remove(path)
	except IndexError:
		pass
if __name__ == "__main__":
	sys.exit(appExec()) 