import os
import sys
import re
import logging
import json
import pytz
import base64
import mimetypes
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.message import EmailMessage
from datetime import datetime
from email.utils import parsedate_to_datetime
from tzlocal import get_localzone
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import QPushButton, QProgressBar
from PyQt5.QtCore import Qt, QTimer, QUrl
from PyQt5.QtGui import QDesktopServices

#logging.basicConfig(level=logging.DEBUG)

# We need full access to delete emails
SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]


def get_real_date(date_string):
    if date_string == 'No Date':
        return date_string

    try:
        # Attempt to parse the date with the specific format YYYY.MM.DD-HH.MM.SS.
        parsed_date = datetime.strptime(date_string, '%Y.%m.%d-%H.%M.%S')
    except ValueError:
        # If the specific format fails, try with the standard format.
        try:
            parsed_date = parsedate_to_datetime(date_string)
        except ValueError:
            parsed_date = None

    if parsed_date:
        # Convert the date to the user's local time
        local_tz = get_localzone()
        local_date = parsed_date.astimezone(local_tz)
        # Format the date according to a specific format
        formatted_date = local_date.strftime("%Y-%m-%d %H:%M:%S %Z")
        return formatted_date
    else:
        return 'Invalid Date'


def convert_expiry_to_local_time(expiry_utc):
    local_timezone = get_localzone()
    utc_timezone = pytz.utc
    expiry_utc = utc_timezone.localize(expiry_utc)
    expiry_local = expiry_utc.astimezone(local_timezone)
    return expiry_local


def authenticate():
    creds = None
    token_path = "token.json"

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                print("Token refreshed:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
            except Exception as e:
                print(f"Error refreshing token: {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("New authorization:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("New authorization:")
            print(f"Access Token: {creds.token}")
            print(f"Refresh Token: {creds.refresh_token}")
            print("Expiry:", convert_expiry_to_local_time(creds.expiry))

        with open(token_path, "w") as token:
            token.write(creds.to_json())
    else:
        print("Existing token:")
        print(f"Access Token: {creds.token}")
        print(f"Refresh Token: {creds.refresh_token}")
        print("Expiry:", convert_expiry_to_local_time(creds.expiry))

    return creds


def load_icons():
    icon_ids = {
        'INBOX': 'icons/inbox.png',
        'SENT': 'icons/sent.png',
        'STARRED': 'icons/starred.png',
        'IMPORTANT': 'icons/important.png',
        'UNREAD': 'icons/unread.png',
        'DRAFT': 'icons/draft.png',
        'TRASH': 'icons/trash.png',
        'SPAM': 'icons/spam.png',
    }

    icons = {}
    for label, icon_path in icon_ids.items():
        icon = QtGui.QIcon(icon_path)
        icons[label] = icon

    return icons


def list_labels(service):
    try:
        response = service.users().labels().list(userId='me').execute()
        labels = response['labels']

        label_order = {
            'INBOX': 1,
            'SENT': 2,
            'STARRED': 3,
            'IMPORTANT': 4,
            'UNREAD': 5,
            'DRAFT': 6,
            'TRASH': 7,
            'SPAM': 8,
            'system': 100,
            'user': 200
        }

        def sort_key(label):
            # Get the sorting order by name and by type
            order = label_order.get(label['name'].upper(), float('inf'))
            type_order = label_order.get(label['type'], float('inf'))

            # If the type is 'user', sort by name and sub-label depth
            if label['type'] == 'user':
                parts = label['name'].split('/')
                # Use an iterative loop to get the depth of the sub-label
                depth = len(parts)
                # Create a sorting key combining name and depth
                return type_order, parts[0], depth, label['name']

            return type_order, order

        sorted_labels = sorted(labels, key=sort_key)

        label_data = []
        unread_message_subjects = []

        # Collect the subjects of the UNREAD messages
        unread_label_id = None
        for label in sorted_labels:
            if label['name'].upper() == 'UNREAD':
                unread_label_id = label['id']
                break

        if unread_label_id:
            unread_messages = list_messages(service, unread_label_id)
            unread_message_subjects = [get_message_subject(service, message['id']) for message in unread_messages]

        for label in sorted_labels:
            messages = list_messages(service, label['id'])
            num_messages = len(messages)
            label_name = f"{label['name']} ({num_messages})" if num_messages > 0 else label['name']

            has_unread_messages = any(subject in unread_message_subjects for subject in [get_message_subject(service, message['id']) for message in messages])
            unread_messages_count = sum(1 for message in messages if get_message_subject(service, message['id']) in unread_message_subjects)

            if has_unread_messages:
                if unread_messages_count > 0:
                    if not re.search(r'\bUNREAD\b', label['name'], re.IGNORECASE):
                        label_name += f" | Unread {unread_messages_count}"
                color = QtGui.QColor(0, 0, 139)  # Dark blue
                font = QtGui.QFont()
                font.setBold(True)
            else:
                color = QtGui.QColor(0, 0, 0)
                font = QtGui.QFont()
                font.setBold(False)

            label_data.append((label_name, color, label['id'], font))

        return label_data

    except HttpError as error:
        QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")


def list_messages(service, label_id):
    try:
        response = service.users().messages().list(userId='me', labelIds=[label_id]).execute()
        messages = response.get('messages', [])
        return messages
    except HttpError as error:
        QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")
        return []


def get_message_subject(service, message_id):
    try:
        msg = service.users().messages().get(userId='me', id=message_id).execute()
        headers = msg['payload']['headers']
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
        return subject
    except HttpError as error:
        QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")
        return 'No Subject'


class GmailManager(QtWidgets.QMainWindow):
    custom_interval = None

    def __init__(self, service):
        super().__init__()

        self.downloaded_images = []
        self.image_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloaded_images')
        if not os.path.exists(self.image_directory):
            os.makedirs(self.image_directory)

        self.downloaded_pdf = []
        self.pdf_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'downloaded_pdf')
        if not os.path.exists(self.pdf_directory):
            os.makedirs(self.pdf_directory)

        self.service = service
        self.check_frequency = 180000  # Initialize the default check frequency
        self.timer_active = True

        self.current_action = None
        self.action_objects = []
        self.setup_menu()

        # Create and start QTimer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_for_new_and_unread_messages)
        self.update_timer()

        self.progress_bar = QProgressBar()
        self.initUI()
        self.check_for_new_and_unread_messages()  # Start automatically checking for new messages

    def initUI(self):
        self.setWindowTitle('Gmail Manager')
        self.setGeometry(100, 100, 1200, 800)

        toolbar = self.addToolBar('Toolbar')
        new_message = QPushButton("New Message")
        toolbar.addWidget(new_message)
        new_message.clicked.connect(self.new_message)

        refresh_action = QPushButton('Refresh', self)
        toolbar.addWidget(refresh_action)
        refresh_action.clicked.connect(self.refresh_labels)

        delete_action = QPushButton('Delete', self)
        toolbar.addWidget(delete_action)
        delete_action.clicked.connect(self.delete_message)

        mark_as_read_action = QPushButton('Mark as Read', self)
        toolbar.addWidget(mark_as_read_action)
        mark_as_read_action.clicked.connect(self.mark_message_as_read_from_button)

        mark_as_not_read_action = QPushButton('Mark as Not Read', self)
        toolbar.addWidget(mark_as_not_read_action)
        mark_as_not_read_action.clicked.connect(self.mark_message_as_not_read_from_button)

        empty_trash_action = QPushButton('Empty Trash', self)
        toolbar.addWidget(empty_trash_action)
        empty_trash_action.clicked.connect(self.empty_trash)

        quit_action = QPushButton('Quit', self)
        toolbar.addWidget(quit_action)
        quit_action.clicked.connect(self.close)

        # Create an icon to indicate UNREAD messages
        self.unread_message_icon = QtGui.QIcon("icons/unread_message_notif.png")
        # Create the action to indicate UNREAD messages in the toolbar
        self.unread_message_action = QtWidgets.QAction(self.unread_message_icon, "(No UNREAD messages)", self)
        toolbar.addAction(self.unread_message_action)

        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setFormat(" Refreshing labels & messages... %p%")
        self.progress_bar.setStyleSheet("QProgressBar {border: 2px solid grey; border-radius: 5px; background-color: #FFFFFF;} QProgressBar::chunk {background-color: #37c9e1;}")
        layout.addWidget(self.progress_bar)
        self.progress_bar.setVisible(False)

        self.label_list = QtWidgets.QListWidget()
        self.message_list = QtWidgets.QListWidget()
        self.message_content = QWebEngineView()

        # Enable multiple selection in the messages list
        self.message_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        self.label_list.itemSelectionChanged.connect(self.on_label_selected)
        self.message_list.itemSelectionChanged.connect(self.on_message_selected)

        self.splitter1 = QtWidgets.QSplitter(Qt.Horizontal)
        self.splitter2 = QtWidgets.QSplitter(Qt.Vertical)

        self.splitter1.addWidget(self.label_list)
        self.splitter1.addWidget(self.splitter2)

        self.splitter2.addWidget(self.message_list)
        self.splitter2.addWidget(self.message_content)

        layout.addWidget(self.splitter1)

        self.refresh_labels()

        # Default to selecting the label "INBOX" on widget startup
        inbox_item = self.find_label_item(r'^INBOX\b.*')
        if inbox_item:
            inbox_index = self.label_list.indexFromItem(inbox_item).row()
            self.label_list.setCurrentRow(inbox_index)

    @staticmethod
    def get_label_id_by_name(service, label_name):
        labels = service.users().labels().list(userId='me').execute()
        for label in labels['labels']:
            if label['name'] == label_name:
                return label['id']
        return None

    def setup_menu(self):
        menubar = self.menuBar()
        self.frequency_menu = menubar.addMenu('Set Check Frequency')

        self.actions = [
            ('1 minute', 60000),
            ('2 minutes', 120000),
            ('3 minutes', 180000),
            ('Custom interval', None),
            ('Disable timer', None)
        ]

        self.action_objects = []

        for text, frequency in self.actions:
            action = QtWidgets.QAction(text, self)
            if frequency is not None:
                action.triggered.connect(lambda _, f=frequency, a=action: self.set_check_frequency(f, a))
            else:
                action.triggered.connect(lambda _, a=action: self.handle_special_action(a))
            self.frequency_menu.addAction(action)
            self.action_objects.append(action)

        # Select the default action based on the default check_frequency
        default_action_index = 2  # Index for 3 minutes
        self.update_selected_action(self.frequency_menu.actions()[default_action_index])

    def handle_special_action(self, action):
        action_text = action.text()
        if action_text == 'Custom interval':
            self.set_custom_interval()
        elif action_text == 'Disable timer':
            self.disable_timer()
        self.update_selected_action(action)

    def set_check_frequency(self, frequency, action):
        self.check_frequency = frequency
        self.timer.stop()
        self.update_timer()
        print(f"Check frequency set to {frequency} milliseconds")
        if not self.timer_active:
            self.timer_active = True
            self.update_timer()
        self.update_selected_action(action)

    def set_custom_interval(self):
        interval, ok = QtWidgets.QInputDialog.getInt(self, 'Custom Interval', 'Enter interval in minutes:', 1, 1, 1440)
        if ok:
            self.check_frequency = interval * 60000
            if not self.timer_active:
                self.timer_active = True
            self.update_timer()
            print(f"Check frequency set to {self.check_frequency} milliseconds")
            self.update_selected_action(self.action_objects[3])  # Custom interval is at index 3
        else:
            self.update_selected_action(self.current_action)  # Keep the current action selected if canceled

    def disable_timer(self):
        self.timer_active = False
        self.update_timer()
        print("Timer disabled")
        self.update_selected_action(self.action_objects[4])  # Disable timer is at index 4

    def update_timer(self):
        if self.timer_active:
            self.timer.start(self.check_frequency)
        else:
            self.timer.stop()

    def update_selected_action(self, action):
        if self.current_action:
            if 'Custom interval' in self.current_action.text():
                self.current_action.setText('Custom interval')
            else:
                self.current_action.setText(self.current_action.text().replace(' [Selected]', ''))

        self.current_action = action
        action_text = action.text()
        if 'Custom interval' in action_text:
            action_text = f'Custom interval ({self.check_frequency // 60000} minutes)'
        self.current_action.setText(f"{action_text} [Selected]")

    def check_for_new_and_unread_messages(self):
        # Logic to check UNREAD messages
        # Use QTimer to schedule periodic checks

        self.refresh_labels()

        # Check UNREAD messages in the UNREAD label
        label_name = 'UNREAD'
        label_id = self.get_label_id_by_name(self.service, label_name)

        if label_id:
            unread_messages = list_messages(self.service, label_id)
            if unread_messages:
                # If UNREAD messages are found in the UNREAD label, update the notification icon
                self.unread_message_action.setEnabled(True)
                self.unread_message_action.setText(f"UNREAD Messages Received")
            else:
                # Disable the action if no UNREAD messages are detected
                self.unread_message_action.setEnabled(False)
        else:
            print("Label '{}' not found.".format(label_name))

    def refresh_labels(self, select_label=None):
        # Display the progress bar before processing.
        self.process_data_with_progress()
        # Save the index of the previously selected row and the label name
        previous_index = self.label_list.currentRow()
        previous_label_name = None
        selected_items = self.label_list.selectedItems()
        if selected_items:
            previous_label_name = selected_items[0].text()  # Save the name of the previous label
            #print("Label before :", previous_label_name)
        #else:
            #print("No label selected before refreshing")

        #print("Index of the previously selected row before refreshing :", previous_index)

        self.label_list.clear()
        self.labels = list_labels(self.service)

        # Load the icons
        icons = load_icons()

        for label_name, label_color, label_id, font in self.labels:
            item = QtWidgets.QListWidgetItem()
            item.setData(Qt.UserRole, label_id)
            base_label_name = label_name.split()[0]
            if base_label_name in icons:
                icon = icons[base_label_name]
                item.setIcon(icon)
            item.setText(label_name)
            if label_color:
                item.setForeground(label_color)
            if font:
                item.setFont(font)
            self.label_list.addItem(item)

        # Adjust the size of splitter1 based on the maximum length of the labels
        max_label_length = max([self.label_list.fontMetrics().boundingRect(label[0]).width() for label in self.labels])
        self.label_list.setFixedWidth(max_label_length + 50)  # Add a margin for some extra space.
        self.splitter1.setSizes([max_label_length + 20, self.width() - max_label_length - 20])

        # Try to retrieve the label by its name
        if previous_label_name:
            #print("Name of the previously active label :", previous_label_name)
            escaped_previous_label_name = re.escape(previous_label_name)
            escaped_previous_label_name = escaped_previous_label_name.replace('\\(', '\\(').replace('\\)', '\\)')
            previous_item = self.find_label_item(escaped_previous_label_name)
            if previous_item:
                previous_index = self.label_list.indexFromItem(previous_item).row()

        # Restore the selection of the previously active label by index
        #print("Index of the restored row after refreshing :", previous_index)
        self.label_list.setCurrentRow(previous_index)

        # Search for and select the specified label
        if select_label:
            label_item = self.find_label_item(select_label)
            if not label_item:
                # If the specified label is not found, try to find a matching label
                # with a regular pattern (e.g., "SENT (number)")
                pattern = re.compile(rf"{re.escape(select_label)}(?:\s*\(\d+\))?$")
                for item in self.label_list.findItems(pattern.pattern, Qt.MatchRegExp):
                    label_item = item
                    break
            if label_item:
                label_index = self.label_list.indexFromItem(label_item).row()
                self.label_list.setCurrentRow(label_index)
            else:
                print(f"Le libellé '{select_label}' n'a pas été trouvé.")

        # # Debug - Get the name of the selected label after refreshing
        # selected_items = self.label_list.selectedItems()
        # if selected_items:
        #     current_label_name = selected_items[0].text()
        #     print("Label after :", current_label_name)
        # else:
        #     print("No label selected after refreshing")
        # # End Debug

        # Check if there are any messages left in the list of UNREAD
        # Search for the first label starting with "UNREAD" in the list of labels in the user interface
        unread_label_id = None
        for index in range(self.label_list.count()):
            label_item = self.label_list.item(index)
            label_name = label_item.text()
            if re.match(r'^UNREAD', label_name, re.IGNORECASE):
                unread_label_id = label_item.data(Qt.UserRole)
                break
        if unread_label_id:
            unread_messages = list_messages(self.service, unread_label_id)
            if len(unread_messages) > 0:
                # If UNREAD messages are found in the UNREAD label, update the notification icon
                self.unread_message_action.setEnabled(True)
                self.unread_message_action.setText(f"UNREAD Messages Received")

    def show_progress_bar(self):
        self.progress_bar.setVisible(True)

    def hide_progress_bar(self):
        self.progress_bar.setVisible(False)

    def process_data_with_progress(self):
        self.show_progress_bar()
        total_steps = 100
        for i in range(total_steps):
            progress_value = (i + 1) * 100 / total_steps
            self.progress_bar.setValue(int(progress_value))
            QtCore.QThread.msleep(100)
        self.hide_progress_bar()

    def find_label_item(self, label_name):
        for item in self.label_list.findItems(label_name, Qt.MatchRegExp):
            return item
        return None

    def clear_web_view(self):
        self.message_content.setUrl(QtCore.QUrl("about:blank"))

    def on_label_selected(self):
        self.message_list.clear()
        selected_items = self.label_list.selectedItems()
        if not selected_items:
            return
        label_id = selected_items[0].data(Qt.UserRole)
        messages = list_messages(self.service, label_id)

        # Search for the first label starting with "UNREAD" in the list of labels in the user interface
        unread_label_id = None
        for index in range(self.label_list.count()):
            label_item = self.label_list.item(index)
            label_name = label_item.text()
            if re.match(r'^UNREAD', label_name, re.IGNORECASE):
                unread_label_id = label_item.data(Qt.UserRole)
                break

        if unread_label_id:
            unread_messages = list_messages(self.service, unread_label_id)
            unread_message_subjects = [get_message_subject(self.service, message['id']) for message in unread_messages]
        else:
            unread_message_subjects = []

        for message in messages:
            subject = get_message_subject(self.service, message['id'])
            item = QtWidgets.QListWidgetItem(subject)
            item.setData(Qt.UserRole, message['id'])

            # Check if the subject of the message is in the list of subjects of unread messages
            if subject in unread_message_subjects:
                item.setForeground(QtGui.QColor(0, 0, 139))  # Dark blue for unread messages
                font = item.font()  # Get the current font of the item.
                font.setBold(True)
                item.setFont(font)  # Apply the modified font to the item.

            self.message_list.addItem(item)

        # Clear the message content if there are no messages for the selected label
        if not messages:
            self.clear_web_view()

        # Select the first item in the list of messages
        if self.message_list.count() > 0:
            self.message_list.setCurrentRow(0)

    def on_message_selected(self):
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        # Delete the previously downloaded PNG files and PDF files .
        self.delete_downloaded_images()
        self.delete_downloaded_pdf()
        # Clear the list of downloaded PNG files and PDF files.
        self.downloaded_images = []
        self.downloaded_pdf = []

        message_id = selected_items[0].data(Qt.UserRole)
        message = self.service.users().messages().get(userId='me', id=message_id, format="full").execute()
        #print(json.dumps(self.service.users().messages().get(userId='me', id=message_id, format="full").execute(), indent=2))
        payload = message.get('payload', {})
        parts = payload.get('parts', [])

        headers = {header['name']: header['value'] for header in payload.get('headers', [])}
        subject = headers.get('Subject', 'No Subject')
        date = headers.get('Date', 'No Date')
        from_email = headers.get('From', 'No Sender')
        to_emails = headers.get('To', 'No Recipient')

        # Use regular expressions to clean up email addresses
        from_email_cleaned = re.findall(r'<([^>]+)>', from_email)
        if from_email_cleaned:
            from_email = from_email_cleaned[0].strip('"')
        else:
            from_email = from_email.strip('"')

        to_emails_cleaned = re.findall(r'<([^>]+)>', to_emails)
        if to_emails_cleaned:
            to_emails = ', '.join(to_emails_cleaned)
        else:
            to_emails = to_emails  # In case there are no angle brackets

        real_date = get_real_date(date)
        date_str = f"<strong>Date:</strong> {real_date}"
        from_email_str = f"<strong>From:</strong> {from_email}"
        to_emails_str = f"<strong>To:</strong> {to_emails}"

        if 'text/html' in [part.get('mimeType') for part in parts]:
            attachments = GmailManager.get_attachments(self, message_id)
            cid_to_path = {}  # Dictionary to map CIDs to local paths
            for attachment in attachments:
                saved_path = self.save_attachment(self.image_directory, attachment)
                if saved_path:
                    cid_to_path[attachment['filename']] = saved_path
                    self.downloaded_images.append(saved_path)  # Add the file path to the list
                    #print(f"Mapping cid '{attachment['filename']}' to local path '{saved_path}'")
                else:
                    print(f"Failed to save attachment '{attachment['filename']}'.")

            content = self.extract_html([payload])
            script_dir = os.path.dirname(os.path.abspath(__file__))

            for cid, path in cid_to_path.items():
                #print(f"Replacing src for cid '{cid}' with local path '{path}'")
                # Add the prefix file:// and the absolute path of the script's directory to the image path.
                absolute_path = f"file://{path}"
                content = re.sub(r'src=["\']cid:{}["\']'.format(re.escape(cid)), f'src="{absolute_path}"', content)

            if self.downloaded_pdf:
                if len(self.downloaded_pdf) > 1:
                    content += "<p><strong>PDF Attachments:</strong></p>"
                    for filename in self.downloaded_pdf:
                        file_path = os.path.join(self.pdf_directory, filename)
                        file_pdf = f"file://{file_path}"
                        content += f"<p>&#8226; <a href=\"{file_pdf}\">{filename}</a></p>"
                else:
                    filename = self.downloaded_pdf[0]
                    file_path = os.path.join(self.pdf_directory, filename)
                    file_pdf = f"file://{file_path}"
                    content += f"<p><strong>PDF Attachment:</strong> <a href=\"{file_pdf}\">{filename}</a></p>"

            # logic to detect links to PDF files and open them in the browser.
            self.message_content.page().profile().downloadRequested.connect(self.on_pdf_requested)
            #print(content)

            # Construct full HTML content
            full_content = f"""
            <html>
            <body>
                <h2 style='margin-top: 10px;'>{subject}</h2>
                <div>{date_str}</div>
                <div>{from_email_str}</div>
                <div>{to_emails_str}</div>
                <hr>
                {content}
            </body>
            </html>
            """

            #print(full_content)

            base_url = QtCore.QUrl.fromLocalFile(script_dir + '/')
            self.message_content.setHtml(full_content, base_url)
        else:
            attachments = GmailManager.get_attachments(self, message_id)
            cid_to_path = {}  # Dictionary to map CIDs to local paths
            for attachment in attachments:
                saved_path = self.save_attachment(self.image_directory, attachment)
                if saved_path:
                    cid_to_path[attachment['filename']] = saved_path
                    self.downloaded_images.append(saved_path)  # Add the file path to the list
                    #print(f"Mapping cid '{attachment['filename']}' to local path '{saved_path}'")
                else:
                    print(f"Failed to save attachment '{attachment['filename']}'.")

            content = self.extract_data([payload])
            script_dir = os.path.dirname(os.path.abspath(__file__))

            for cid, path in cid_to_path.items():
                #print(f"Replacing src for cid '{cid}' with local path '{path}'")
                # Add the prefix file:// and the absolute path of the script's directory to the image path.
                absolute_path = f"file://{path}"
                content = re.sub(r'src=["\']cid:{}["\']'.format(re.escape(cid)), f'src="{absolute_path}"', content)

            if self.downloaded_pdf:
                if len(self.downloaded_pdf) > 1:
                    content += "<p><strong>PDF Attachments:</strong></p>"
                    for filename in self.downloaded_pdf:
                        file_path = os.path.join(self.pdf_directory, filename)
                        file_pdf = f"file://{file_path}"
                        content += f"<p>&#8226; <a href=\"{file_pdf}\">{filename}</a></p>"
                else:
                    filename = self.downloaded_pdf[0]
                    file_path = os.path.join(self.pdf_directory, filename)
                    file_pdf = f"file://{file_path}"
                    content += f"<p><strong>PDF Attachment:</strong> <a href=\"{file_pdf}\">{filename}</a></p>"

            # logic to detect links to PDF files and open them in the browser.
            self.message_content.page().profile().downloadRequested.connect(self.on_pdf_requested)
            #print(content)

            # Construct full HTML content
            full_content = f"""
            <html>
            <body>
                <h2 style='margin-top: 10px;'>{subject}</h2>
                <div>{date_str}</div>
                <div>{from_email_str}</div>
                <div>{to_emails_str}</div>
                <hr>
                {content}
            </body>
            </html>
            """

            #print(full_content)

            base_url = QtCore.QUrl.fromLocalFile(script_dir + '/')
            self.message_content.setHtml(full_content, base_url)

    def mark_message_as_read_from_button(self):
        # Retrieve IDs of selected messages in the list of messages
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_ids = [item.data(Qt.UserRole) for item in selected_items]
        #print("Selected message IDs:", message_ids)
        # Call the method to mark the messages as read
        self.mark_messages_as_read(message_ids)

    def mark_messages_as_read(self, message_ids):
        try:
            for message_id in message_ids:
                modify_request = {'removeLabelIds': ['UNREAD']}
                self.service.users().messages().modify(userId='me', id=message_id, body=modify_request).execute()
                #print(f"Message with ID {message_id} marked as read successfully.")
            self.check_for_new_and_unread_messages()
            # Check if there are any messages left in the list of UNREAD
            # Search for the first label starting with "UNREAD" in the list of labels in the user interface
            unread_label_id = None
            for index in range(self.label_list.count()):
                label_item = self.label_list.item(index)
                label_name = label_item.text()
                if re.match(r'^UNREAD', label_name, re.IGNORECASE):
                    unread_label_id = label_item.data(Qt.UserRole)
                    break
            if unread_label_id:
                unread_messages = list_messages(self.service, unread_label_id)
                if len(unread_messages) == 0:
                    # Disable the action if no UNREAD messages are detected
                    self.unread_message_action.setEnabled(False)
        except HttpError as error:
            QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred while marking the messages as read: {error}")

    def mark_message_as_not_read_from_button(self):
        # Retrieve IDs of selected messages in the list of messages
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_ids = [item.data(Qt.UserRole) for item in selected_items]
        #print("Selected message IDs:", message_ids)  # Print selected message IDs for debugging
        # Call the method to mark the messages as unread
        self.mark_messages_as_not_read(message_ids)

    def mark_messages_as_not_read(self, message_ids):
        try:
            for message_id in message_ids:
                modify_request = {'addLabelIds': ['UNREAD']}
                self.service.users().messages().modify(userId='me', id=message_id, body=modify_request).execute()
                #print(f"Message with ID {message_id} marked as not read successfully.")
            self.check_for_new_and_unread_messages()
        except HttpError as error:
            QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred while marking the messages as not read: {error}")

    def delete_downloaded_images(self):
        #print("Deleting downloaded images...")
        for file_path in self.downloaded_images:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    #print(f"Deleted file '{file_path}'")
            except Exception as e:
                print(f"Failed to delete file '{file_path}': {e}")

    def delete_downloaded_pdf(self):
        #print("Deleting downloaded PDFs...")
        for file_name in self.downloaded_pdf:
            file_path = os.path.join(self.pdf_directory, file_name)  # Construct the full file path
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    #print(f"Deleted file '{file_path}'")
            except Exception as e:
                print(f"Failed to delete file '{file_path}': {e}")

    @staticmethod
    def get_content_id(headers):
        for header in headers:
            if header['name'].lower() == 'content-id':
                return header['value'].strip('<>')
        return None

    @staticmethod
    def get_attachments(self, message_id):
        try:
            #print("Fetching message attachments...")
            message = self.service.users().messages().get(userId='me', id=message_id).execute()

            attachments = []
            if 'parts' in message['payload']:
                #print("Processing message parts for attachments...")
                for part in message['payload']['parts']:
                    if 'body' in part and 'attachmentId' in part['body']:
                        #print(f"Downloading attachment: {part['filename']}")
                        attachment_data = self.service.users().messages().attachments().get(
                            userId='me', messageId=message_id, id=part['body']['attachmentId']
                        ).execute()
                        if 'data' in attachment_data:
                            content_id = self.get_content_id(part['headers'])
                            if content_id:
                                attachments.append({'filename': content_id, 'data': attachment_data['data']})
                                #print(f"Attachment '{content_id}' downloaded.")
                            else:
                                print("No Content-ID found.")
                        else:
                            print("No attachment data found.")
            else:
                print("No parts found in message.")

            return attachments

        except Exception as e:
            print('An error occurred:', e)
            return []

    @staticmethod
    def save_attachment(directory, attachment_data):
        try:
            filename = attachment_data['filename']
            filename = re.sub(r'[\\/*?:"<>|]', "", filename) + ".png"
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            filepath = os.path.join(directory, filename)
            with open(filepath, 'wb') as f:
                f.write(base64.urlsafe_b64decode(attachment_data['data']))
            #print(f"Attachment '{filename}' saved to '{directory}'.")
            return filepath
        except Exception as e:
            print("An error occurred while saving attachment:", e)
            return None

    @staticmethod
    def open_pdf_in_browser(pdf_path):
        QDesktopServices.openUrl(QUrl(pdf_path))

    def on_pdf_requested(self, download):
        url = download.url().toString()
        if url.lower().endswith('.pdf'):
            self.open_pdf_in_browser(url)

    def extract_data(self, parts):
        result = ""
        max_size = 0
        pdf_ids_downloaded = set()

        for part in parts:
            if 'body' in part:
                body_size = part['body']['size']
                if body_size > max_size:
                    max_size = body_size
                    if 'data' in part['body']:
                        data = part['body']['data']
                        result = GmailManager.decode_base64(data).decode("utf-8")
                elif 'parts' in part:
                    sub_data = self.extract_data(part['parts'])
                    sub_size = len(sub_data)
                    if sub_size > max_size:
                        result = sub_data
                        max_size = sub_size

            # Check if the part contains a PDF; if so, download it
            if part.get('mimeType') == 'application/pdf' and part.get('filename'):
                part_id = part.get('partId')
                if part_id not in pdf_ids_downloaded:
                    filename = part['filename']
                    selected_items = self.message_list.selectedItems()
                    if not selected_items:
                        return
                    message_id = selected_items[0].data(Qt.UserRole)
                    attachment = self.service.users().messages().attachments().get(userId='me', messageId=message_id, id=part['body']['attachmentId']).execute()
                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    pdf_path = os.path.join(self.pdf_directory, filename)
                    with open(pdf_path, 'wb') as f:
                        f.write(file_data)

                    pdf_ids_downloaded.add(part_id)
                    self.downloaded_pdf.append(filename)

                    #print(f"Downloaded PDF part_id: {part_id}")

        #print(f"PDF part IDs downloaded: {pdf_ids_downloaded}")
        return result

    def find_matching_part(self, parts, mime_type, max_depth, current_depth=0):
        matching_part = None
        max_size = 0
        pdf_ids_downloaded = set()

        for part in parts:
            if 'mimeType' in part and part['mimeType'] == mime_type:
                if 'body' in part and part['body'] and 'data' in part['body']:
                    if part['body']['size'] > max_size:
                        matching_part = part
                        max_size = part['body']['size']

            if 'parts' in part and current_depth < max_depth:
                matched_part = self.find_matching_part(part['parts'], mime_type, max_depth, current_depth=current_depth+1)
                if matched_part:
                    if matched_part['body']['size'] > max_size:
                        matching_part = matched_part
                        max_size = matched_part['body']['size']

            # Check if the part contains a PDF; if so, download it
            if part.get('mimeType') == 'application/pdf' and part.get('filename'):
                part_id = part.get('partId')
                if part_id not in pdf_ids_downloaded:
                    filename = part['filename']
                    selected_items = self.message_list.selectedItems()
                    if not selected_items:
                        return
                    message_id = selected_items[0].data(Qt.UserRole)
                    attachment = self.service.users().messages().attachments().get(userId='me', messageId=message_id, id=part['body']['attachmentId']).execute()
                    file_data = base64.urlsafe_b64decode(attachment['data'])
                    pdf_path = os.path.join(self.pdf_directory, filename)
                    with open(pdf_path, 'wb') as f:
                        f.write(file_data)

                    pdf_ids_downloaded.add(part_id)
                    self.downloaded_pdf.append(filename)

                    #print(f"Downloaded PDF part_id: {part_id}")

        #print(f"PDF part IDs downloaded: {pdf_ids_downloaded}")
        return matching_part

    def extract_html(self, parts, max_depth=3):
        matching_part = self.find_matching_part(parts, 'text/html', max_depth)
        if not matching_part:
            return ""

        if 'body' in matching_part and matching_part['body']:
            if 'data' in matching_part['body']:
                data = matching_part['body']['data']

                # Decode the data in UTF-8
                html_data = GmailManager.decode_base64(data).decode('utf-8')

                # Search for the <meta> tag in the HTML content
                meta_regex = r'<meta\s+name="viewport"\s+content="([^"]*)"\s*>'
                match = re.search(meta_regex, html_data)

                # If the <meta> tag is found, replace semicolons with commas in its content
                if match:
                    content_with_commas = match.group(1).replace(';', ',')
                    html_data_with_commas = re.sub(meta_regex, lambda m: f'<meta name="viewport" content="{content_with_commas}">', html_data)
                    return html_data_with_commas
                else:
                    return html_data
        return ""

    @staticmethod
    def decode_base64(data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += '=' * missing_padding
        return base64.urlsafe_b64decode(data)

    def new_message(self):
        compose_dialog = ComposeDialog(self.service, self)
        compose_dialog.exec_()

    def delete_message(self):
        # Retrieve IDs of selected messages in the list of messages
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_ids = [item.data(Qt.UserRole) for item in selected_items]
        #print("Selected message IDs:", message_ids)  # Print selected message IDs for debugging
        if len(message_ids) == 1:
            reply = QtWidgets.QMessageBox.question(self, 'Delete Message', 'Are you sure you want to delete this message?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        else:
            reply = QtWidgets.QMessageBox.question(self, 'Delete Message', 'Are you sure you want to delete these messages?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            try:

                for message_id in message_ids:
                    # Clear the message content (`message_content` is a QWebEngineView)
                    self.message_content.deleteLater()  # Delete the old QWebEngineView instance
                    self.message_content = QWebEngineView()  # Create a new instance
                    self.splitter2.replaceWidget(1, self.message_content)  # Replace the old instance with the new one in the splitter

                    # Remove the corresponding item from the list of messages
                    items_to_remove = [item for item in self.message_list.findItems("", Qt.MatchContains) if item.data(Qt.UserRole) == message_id]
                    for item in items_to_remove:
                        self.message_list.takeItem(self.message_list.row(item))

                    self.service.users().messages().delete(userId='me', id=message_id).execute()
                    #QtWidgets.QMessageBox.information(self, 'Message Deleted', 'The message has been deleted.')
                    #print(f"Message with ID {message_id} has been deleted successfully.")

                # Create a QListWidgetItem to hold the refreshing text
                refreshing_item = QtWidgets.QListWidgetItem(self.message_list)
                refreshing_item.setSizeHint(QtCore.QSize(200, 50))  # Set the size of the item
                refreshing_widget = RefreshingText()

                # Set the widget as the item's widget
                self.message_list.setItemWidget(refreshing_item, refreshing_widget)

                # Check for new and unread messages
                self.check_for_new_and_unread_messages()

                # Select the first item in the list of messages
                if self.message_list.count() > 0:
                    self.message_list.setCurrentRow(0)

            except HttpError as error:
                QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")

    def empty_trash(self):
        reply = QtWidgets.QMessageBox.question(self, 'Empty Trash', 'Are you sure you want to empty the trash?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)

        if reply == QtWidgets.QMessageBox.Yes:
            try:
                creds = authenticate()
                service = build('gmail', 'v1', credentials=creds)
                trash_label_id = 'TRASH'
                messages = list_messages(service, trash_label_id)
                for message in messages:
                    self.service.users().messages().delete(userId='me', id=message['id']).execute()
                QtWidgets.QMessageBox.information(self, 'Trash Emptied', 'The trash has been emptied.')
                self.refresh_labels()
            except HttpError as error:
                QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")


class ComposeDialog(QtWidgets.QDialog):
    def __init__(self, service, parent=None):
        super().__init__(parent)
        self.service = service
        self.attachments = []
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Compose New Message')
        self.setGeometry(300, 300, 600, 400)

        layout = QtWidgets.QVBoxLayout()

        self.to_field = QtWidgets.QLineEdit()
        self.to_field.setPlaceholderText('To')
        layout.addWidget(self.to_field)

        self.subject_field = QtWidgets.QLineEdit()
        self.subject_field.setPlaceholderText('Subject')
        layout.addWidget(self.subject_field)

        self.body_field = QtWidgets.QTextEdit()
        layout.addWidget(self.body_field)

        attach_button = QtWidgets.QPushButton('Attach File')
        attach_button.clicked.connect(self.attach_file)
        layout.addWidget(attach_button)

        button_layout = QtWidgets.QHBoxLayout()
        send_button = QtWidgets.QPushButton('Send')
        send_button.clicked.connect(self.send_message)
        button_layout.addWidget(send_button)

        save_draft_button = QtWidgets.QPushButton('Save Draft')
        save_draft_button.clicked.connect(self.save_draft)
        button_layout.addWidget(save_draft_button)

        cancel_button = QtWidgets.QPushButton('Cancel')
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def attach_file(self):
        options = QtWidgets.QFileDialog.Options()
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Attach File", "", "All Files (*);;Text Files (*.txt);;Images (*.png *.jpg);;PDF Files (*.pdf)", options=options)
        if file_name:
            self.attachments.append(file_name)
            QtWidgets.QMessageBox.information(self, 'Success', f'File {file_name} attached successfully.')

    def send_message(self):
        to = self.to_field.text()
        subject = self.subject_field.text()
        body = self.body_field.toPlainText()

        if not to or not subject or not body:
            QtWidgets.QMessageBox.warning(self, 'Warning', 'All fields are required.')
            return

        try:
            message = EmailMessage()
            message.set_content(body)
            message['To'] = to
            message['Subject'] = subject

            for file_path in self.attachments:
                file_name = os.path.basename(file_path)
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                    maintype, subtype = mimetypes.guess_type(file_path)[0].split('/')
                    message.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_name)

            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            create_message = {
                'raw': raw_message
            }

            self.service.users().messages().send(userId='me', body=create_message).execute()
            QtWidgets.QMessageBox.information(self, 'Success', 'Message sent successfully.')
            # Refresh the labels in the parent window and select the "SENT" label
            self.parent().refresh_labels(select_label="SENT")
            self.accept()

        except HttpError as error:
            QtWidgets.QMessageBox.critical(self, 'Error', f'An error occurred: {error}')

    def save_draft(self):
        to = self.to_field.text()
        subject = self.subject_field.text()
        body = self.body_field.toPlainText()

        if not subject or not body:
            QtWidgets.QMessageBox.warning(self, 'Warning', 'Subject and body fields are required to save a draft.')
            return

        try:
            message = EmailMessage()
            message.set_content(body)
            message['To'] = to
            message['Subject'] = subject

            for file_path in self.attachments:
                file_name = os.path.basename(file_path)
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                    maintype, subtype = mimetypes.guess_type(file_path)[0].split('/')
                    message.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_name)

            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            create_draft = {
                'message': {
                    'raw': raw_message
                }
            }

            self.service.users().drafts().create(userId='me', body=create_draft).execute()
            QtWidgets.QMessageBox.information(self, 'Success', 'Draft saved successfully.')
            # Refresh the labels in the parent window and select the "DRAFT" label
            self.parent().refresh_labels(select_label="DRAFT")
            self.accept()

        except HttpError as error:
            QtWidgets.QMessageBox.critical(self, 'Error', f'An error occurred: {error}')


class RefreshingText(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout()
        self.label = QtWidgets.QLabel("Refreshing messages list ...")
        self.label.setStyleSheet("color: blue;")
        layout.addWidget(self.label)
        layout.setAlignment(Qt.AlignCenter)
        self.setLayout(layout)


def main():
    creds = authenticate()

    try:
        service = build('gmail', 'v1', credentials=creds)

        app = QtWidgets.QApplication(sys.argv)
        window = GmailManager(service)
        window.show()
        sys.exit(app.exec_())

    except HttpError as error:
        QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred: {error}")


if __name__ == '__main__':
    main()
