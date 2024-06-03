import os
import base64
import mimetypes
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging
import json
import pytz
from email.message import EmailMessage
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import QTimer
import sys
import re

#logging.basicConfig(level=logging.DEBUG)

# We need full access to delete emails
SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]

def convert_expiry_to_paris_time(expiry_utc):
    utc_timezone = pytz.utc
    paris_timezone = pytz.timezone('Europe/Paris')
    expiry_utc = utc_timezone.localize(expiry_utc)
    expiry_paris = expiry_utc.astimezone(paris_timezone)
    return expiry_paris


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
                print("Expiry:", convert_expiry_to_paris_time(creds.expiry))
            except Exception as e:
                print(f"Error refreshing token: {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("New authorization:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_paris_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("New authorization:")
            print(f"Access Token: {creds.token}")
            print(f"Refresh Token: {creds.refresh_token}")
            print("Expiry:", convert_expiry_to_paris_time(creds.expiry))

        with open(token_path, "w") as token:
            token.write(creds.to_json())
    else:
        print("Existing token:")
        print(f"Access Token: {creds.token}")
        print(f"Refresh Token: {creds.refresh_token}")
        print("Expiry:", convert_expiry_to_paris_time(creds.expiry))

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
            # Sort priority by specific order then by type
            order = label_order.get(label['name'].upper(), float('inf'))
            type_order = label_order.get(label['type'], float('inf'))

            # If the type is 'user', sort by name and subname
            if label['type'] == 'user':
                parts = label['name'].split('/')
                # Use tuples to sort by multiple levels
                return (type_order, parts[0], parts[1] if len(parts) > 1 else '')
            return (type_order, order)

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
        self.service = service
        self.check_frequency = 180000  # Initialize the default check frequency
        self.timer_active = True
        self.initUI()
        self.check_for_unread_messages()  # Start automatically checking for new messages

    def initUI(self):
        self.setWindowTitle('Gmail Manager')
        self.setGeometry(100, 100, 1200, 800)

        toolbar = self.addToolBar('Toolbar')
        new_message_action = QtWidgets.QAction('New Message', self)
        toolbar.addAction(new_message_action)
        new_message_action.triggered.connect(self.new_message)

        refresh_action = QtWidgets.QAction('Refresh', self)
        toolbar.addAction(refresh_action)
        refresh_action.triggered.connect(self.refresh_labels)

        delete_action = QtWidgets.QAction('Delete', self)
        toolbar.addAction(delete_action)
        delete_action.triggered.connect(self.delete_message)

        mark_as_read_action = QtWidgets.QAction('Mark as Read', self)
        toolbar.addAction(mark_as_read_action)
        mark_as_read_action.triggered.connect(self.mark_message_as_read_from_button)

        mark_as_not_read_action = QtWidgets.QAction('Mark as Not Read', self)
        toolbar.addAction(mark_as_not_read_action)
        mark_as_not_read_action.triggered.connect(self.mark_message_as_not_read_from_button)

        empty_trash_action = QtWidgets.QAction('Empty Trash', self)
        toolbar.addAction(empty_trash_action)
        empty_trash_action.triggered.connect(self.empty_trash)

        quit_action = QtWidgets.QAction('Quit', self)
        toolbar.addAction(quit_action)
        quit_action.triggered.connect(self.close)

        # Create an icon to indicate UNREAD messages
        self.unread_message_icon = QtGui.QIcon("icons/unread_message_notif.png")
        # Create the action to indicate UNREAD messages in the toolbar
        self.unread_message_action = QtWidgets.QAction(self.unread_message_icon, "(No UNREAD messages)", self)
        toolbar.addAction(self.unread_message_action)

        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)

        self.label_list = QtWidgets.QListWidget()
        self.message_list = QtWidgets.QListWidget()
        self.message_content = QtWidgets.QTextEdit()
        self.message_content.setReadOnly(True)

        self.label_list.itemSelectionChanged.connect(self.on_label_selected)
        self.message_list.itemSelectionChanged.connect(self.on_message_selected)

        self.label_list.itemSelectionChanged.connect(self.on_label_selected)
        self.message_list.itemSelectionChanged.connect(self.on_message_selected)

        # self.message_list.model().rowsInserted.connect(self.adjust_splitter)
        # self.message_list.model().rowsRemoved.connect(self.adjust_splitter)

        splitter1 = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.splitter2 = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        splitter1.addWidget(self.label_list)
        splitter1.addWidget(self.splitter2)

        self.splitter2.addWidget(self.message_list)
        self.splitter2.addWidget(self.message_content)

        layout = QtWidgets.QVBoxLayout(central_widget)
        layout.addWidget(splitter1)

        self.splitter1 = splitter1  # Store a reference to splitter1
        self.splitter2 = self.splitter2  # Store a reference to splitter2

        # Set the stretch factors for splitter2
        self.splitter2.setStretchFactor(0, 1)  # The message_list gets one share
        self.splitter2.setStretchFactor(1, 3)  # The message_content gets three shares

        self.refresh_labels()

        # Default to selecting the label "INBOX" on widget startup
        inbox_item = self.find_label_item(r'^INBOX\b.*')
        if inbox_item:
            inbox_index = self.label_list.indexFromItem(inbox_item).row()
            self.label_list.setCurrentRow(inbox_index)

        # Add the dropdown menu to the menu bar to select the check frequency.
        menubar = self.menuBar()
        self.frequency_menu = menubar.addMenu('Set Check Frequency')
        self.one_minute_action = QtWidgets.QAction('1 minute', self)
        self.two_minutes_action = QtWidgets.QAction('2 minutes', self)
        self.three_minutes_action = QtWidgets.QAction('3 minutes', self)
        self.custom_interval_action = QtWidgets.QAction('Custom interval', self)
        self.disable_timer_action = QtWidgets.QAction('Disable timer', self)

        self.frequency_menu.addAction(self.one_minute_action)
        self.frequency_menu.addAction(self.two_minutes_action)
        self.frequency_menu.addAction(self.three_minutes_action)
        self.frequency_menu.addAction(self.custom_interval_action)
        self.frequency_menu.addAction(self.disable_timer_action)

        self.one_minute_action.triggered.connect(lambda: self.set_check_frequency(60000))
        self.two_minutes_action.triggered.connect(lambda: self.set_check_frequency(120000))
        self.three_minutes_action.triggered.connect(lambda: self.set_check_frequency(180000))
        self.custom_interval_action.triggered.connect(self.set_custom_interval)
        self.disable_timer_action.triggered.connect(self.disable_timer)

        # Set initial checkmark for the default frequency
        self.update_frequency_menu()

    # def adjust_splitter(self):
    #     # Adjust the size of splitter2 based on the content of message_list
    #     size_hint = self.message_list.sizeHintForRow(0) * self.message_list.count() + 2 * self.message_list.frameWidth()
    #     margin = 20  # Additional margin
    #     self.message_list.setMaximumHeight(size_hint + margin)
    #     self.splitter2.setSizes([size_hint + margin, self.splitter2.size().height() - (size_hint + margin)])

    @staticmethod
    def get_label_id_by_name(service, label_name):
        labels = service.users().labels().list(userId='me').execute()
        for label in labels['labels']:
            if label['name'] == label_name:
                return label['id']
        return None

    def update_frequency_menu(self):
        self.one_minute_action.setCheckable(True)
        self.two_minutes_action.setCheckable(True)
        self.three_minutes_action.setCheckable(True)
        self.custom_interval_action.setCheckable(True)
        self.disable_timer_action.setCheckable(True)

        if self.timer_active:
            self.one_minute_action.setChecked(self.check_frequency == 60000)
            self.two_minutes_action.setChecked(self.check_frequency == 120000)
            self.three_minutes_action.setChecked(self.check_frequency == 180000)
            if self.check_frequency not in [60000, 120000, 180000]:
                self.custom_interval_action.setChecked(True)
                self.custom_interval_action.setText(f'Custom interval ({self.check_frequency // 60000} minutes)')
            else:
                self.custom_interval_action.setChecked(False)
                self.custom_interval_action.setText('Custom interval')
            self.disable_timer_action.setChecked(False)
        else:
            self.one_minute_action.setChecked(False)
            self.two_minutes_action.setChecked(False)
            self.three_minutes_action.setChecked(False)
            self.custom_interval_action.setChecked(False)
            self.disable_timer_action.setChecked(True)

    def set_check_frequency(self, frequency):
        self.check_frequency = frequency
        self.timer_active = True
        self.update_frequency_menu()
        print(f"Check frequency set to {frequency} milliseconds")

    def set_custom_interval(self):
        interval, ok = QtWidgets.QInputDialog.getInt(self, 'Custom Interval', 'Enter interval in minutes:', 1, 1, 1440)
        if ok:
            self.custom_interval = interval
            self.set_check_frequency(interval * 60000)

    def disable_timer(self):
        self.timer_active = False
        self.update_frequency_menu()
        print("Timer disabled")

    def check_for_unread_messages(self):
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

        # Schedule the next periodic check in 30 seconds
        #QTimer.singleShot(30000, self.check_for_unread_messages)
        # Schedule the next periodic check using the selected frequency
        if self.timer_active:
            QTimer.singleShot(self.check_frequency, self.check_for_unread_messages)

    def refresh_labels(self, select_label=None):
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
            item.setData(QtCore.Qt.UserRole, label_id)
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
        self.label_list.setFixedWidth(max_label_length + 40)  # Add a margin for some extra space.
        self.splitter1.setSizes([max_label_length + 20, self.width() - max_label_length - 20])

        # Try to retrieve the label by its name
        if previous_label_name:
            #print("Nom du label précédemment actif:", previous_label_name)
            escaped_previous_label_name = re.escape(previous_label_name)
            escaped_previous_label_name = escaped_previous_label_name.replace('\\(', '\\(').replace('\\)', '\\)')
            previous_item = self.find_label_item(escaped_previous_label_name)
            if previous_item:
                previous_index = self.label_list.indexFromItem(previous_item).row()

        # Restore the selection of the previously active label by index
        #print("Index de la ligne rétablie après le rafraîchissement :", previous_index)
        self.label_list.setCurrentRow(previous_index)

        # Search for and select the specified label
        if select_label:
            label_item = self.find_label_item(select_label)
            if not label_item:
                # If the specified label is not found, try to find a matching label
                # with a regular pattern (e.g., "SENT (number)")
                pattern = re.compile(rf"{re.escape(select_label)}(?:\s*\(\d+\))?$")
                for item in self.label_list.findItems(pattern.pattern, QtCore.Qt.MatchRegExp):
                    label_item = item
                    break
            if label_item:
                label_index = self.label_list.indexFromItem(label_item).row()
                self.label_list.setCurrentRow(label_index)
            else:
                print(f"Le libellé '{select_label}' n'a pas été trouvé.")

        # Get the name of the selected label after refreshing
        selected_items = self.label_list.selectedItems()
        if selected_items:
            current_label_name = selected_items[0].text()
            #print("Label after :", current_label_name)
        #else:
            #print("No label selected after refreshing")

    def find_label_item(self, label_name):
        for item in self.label_list.findItems(label_name, QtCore.Qt.MatchRegExp):
            return item
        return None

    def on_label_selected(self):
        self.message_list.clear()
        selected_items = self.label_list.selectedItems()
        if not selected_items:
            return
        label_id = selected_items[0].data(QtCore.Qt.UserRole)
        messages = list_messages(self.service, label_id)

        # Search for the first label starting with "UNREAD" in the list of labels in the user interface
        unread_label_id = None
        for index in range(self.label_list.count()):
            label_item = self.label_list.item(index)
            label_name = label_item.text()
            if re.match(r'^UNREAD', label_name, re.IGNORECASE):
                unread_label_id = label_item.data(QtCore.Qt.UserRole)
                break

        if unread_label_id:
            unread_messages = list_messages(self.service, unread_label_id)
            unread_message_subjects = [get_message_subject(self.service, message['id']) for message in unread_messages]
        else:
            unread_message_subjects = []

        for message in messages:
            subject = get_message_subject(self.service, message['id'])
            item = QtWidgets.QListWidgetItem(subject)
            item.setData(QtCore.Qt.UserRole, message['id'])

            # Check if the subject of the message is in the list of subjects of unread messages
            if subject in unread_message_subjects:
                item.setForeground(QtGui.QColor(0, 0, 139))  # Bleu foncé pour les messages non lus
                font = item.font()  # Get the current font of the item.
                font.setBold(True)
                item.setFont(font)  # Apply the modified font to the item.

            self.message_list.addItem(item)

        # Clear the message content if there are no messages for the selected label
        if not messages:
            self.message_content.clear()

        # Select the first item in the list of messages
        if self.message_list.count() > 0:
            self.message_list.setCurrentRow(0)

    def on_message_selected(self):
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_id = selected_items[0].data(QtCore.Qt.UserRole)
        message = self.service.users().messages().get(userId='me', id=message_id, format="full").execute()
        #print(json.dumps(self.service.users().messages().get(userId='me', id=message_id, format="full").execute(), indent=2))
        payload = message.get('payload', {})
        parts = payload.get('parts', [])

        headers = {header['name']: header['value'] for header in payload.get('headers', [])}
        subject = headers.get('Subject', 'No Subject')
        date_str = headers.get('Date', 'No Date')
        from_email = headers.get('From', 'No Sender')
        to_emails = headers.get('To', 'No Recipient')

        content = ""
        if 'text/html' in [part.get('mimeType') for part in parts]:
            content = self.extract_html([payload])
        else:
            content = self.extract_data([payload])

        self.message_content.setHtml(f"<h1>{subject}</h1><p>{date_str}</p><p>From: {from_email}</p><p>To: {to_emails}</p><hr>{content}")

    def mark_message_as_read_from_button(self):
        # Retrieve the ID of the selected message in the list of messages
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_id = selected_items[0].data(QtCore.Qt.UserRole)
        # Call the method to mark the message as read
        self.mark_message_as_read(message_id)

    def mark_message_as_read(self, message_id):
        try:
            modify_request = {'removeLabelIds': ['UNREAD']}
            self.service.users().messages().modify(userId='me', id=message_id, body=modify_request).execute()
            print("Message marked as read successfully.")
            # Refresh the labels to update the list of unread messages
            self.refresh_labels()
            # Check if there are any messages left in the list
            if self.message_list.count() == 0:
                # Disable the action if no UNREAD messages are detected
                self.unread_message_action.setEnabled(False)
        except HttpError as error:
            QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred while marking the message as read: {error}")

    def mark_message_as_not_read_from_button(self):
        # Get the ID of the selected message in the list of messages
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_id = selected_items[0].data(QtCore.Qt.UserRole)
        # Call the method to mark the message as unread
        self.mark_message_as_not_read(message_id)

    def mark_message_as_not_read(self, message_id):
        try:
            modify_request = {'addLabelIds': ['UNREAD']}
            self.service.users().messages().modify(userId='me', id=message_id, body=modify_request).execute()
            print("Message marked as not read successfully.")
            # Refresh the labels to update the list of unread messages
            self.refresh_labels()
        except HttpError as error:
            QtWidgets.QMessageBox.critical(None, "Error", f"An error occurred while marking the message as not read: {error}")

    def extract_data(self, parts):
        result = ""
        for part in parts:
            if 'body' in part and part['body']:
                if 'data' in part['body']:
                    data = part['body']['data']
                    result += self.decode_base64(data).decode("utf-8")
                elif 'attachmentId' in part['body']:
                    attachment_id = part['body']['attachmentId']
                    attachment = self.service.users().messages().attachments().get(userId='me', messageId=message_id, id=attachment_id).execute()
                    data = attachment['data']
                    result += self.decode_base64(data).decode("utf-8")
            elif 'parts' in part and part['parts']:
                if 'mimeType' in part and part["mimeType"] == "multipart/alternative":
                    result += self.extract_data(part['parts'])
                elif 'mimeType' in part and part["mimeType"] == "multipart/mixed":
                    for sub_part in part['parts']:
                        if 'mimeType' in sub_part and sub_part['mimeType'] != "multipart/*":
                            result += self.extract_data([sub_part])
                        else:
                            result += self.extract_data(sub_part['parts'])
                else:
                    return self.extract_data(part['parts'])
        return result

    def find_matching_part(self, parts, mime_type, max_depth, current_depth=0):
        matching_part = None

        for part in parts:
            if 'mimeType' in part and part['mimeType'] == mime_type:
                return part

            if 'parts' in part and current_depth < max_depth:
                matched_part = self.find_matching_part(part['parts'], mime_type, max_depth, current_depth=current_depth+1)
                if matched_part:
                    matching_part = matched_part

        return matching_part

    def extract_html(self, parts, max_depth=3):
        matching_part = self.find_matching_part(parts, 'text/html', max_depth)
        if not matching_part:
            return ""

        if 'body' in matching_part and matching_part['body']:
            if 'data' in matching_part['body']:
                data = matching_part['body']['data']
                html_data = self.decode_base64(data).decode('utf-8')
                return html_data
        return ""

    def decode_base64(self, data):
        missing_padding = 4 - len(data) % 4
        if missing_padding:
            data += '=' * missing_padding
        return base64.urlsafe_b64decode(data)

    def new_message(self):
        compose_dialog = ComposeDialog(self.service, self)
        compose_dialog.exec_()

    def delete_message(self):
        selected_items = self.message_list.selectedItems()
        if not selected_items:
            return
        message_id = selected_items[0].data(QtCore.Qt.UserRole)
        reply = QtWidgets.QMessageBox.question(self, 'Delete Message', 'Are you sure you want to delete this message?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)

        if reply == QtWidgets.QMessageBox.Yes:
            try:
                self.service.users().messages().delete(userId='me', id=message_id).execute()
                QtWidgets.QMessageBox.information(self, 'Message Deleted', 'The message has been deleted.')

                # Clear the list of messages and reset the message content
                self.message_list.clear()
                self.message_content.clear()

                self.refresh_labels()

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

        if not to or not subject or not body:
            QtWidgets.QMessageBox.warning(self, 'Warning', 'All fields are required to save a draft.')
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
