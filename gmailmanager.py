import os
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError, Error
import logging
import pytz
import wx
import wx.html
import wx.html2
import wx.adv
from email.message import EmailMessage

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


def close_frame(event):
    frame.Close()


def list_labels(service):
    try:
        response = service.users().labels().list(userId='me').execute()
        labels = response['labels']

        sorted_labels = sorted(labels, key=lambda x: x['name'].count('/'))

        filtered_labels = [label for label in sorted_labels if label['type'] == 'system']
        filtered_labels += [label for label in sorted_labels if label['type'] != 'system' and label['labelListVisibility'] == 'labelShow']

        label_data = []
        for label in filtered_labels:
            messages = list_messages(service, label['id'])
            num_messages = len(messages)
            label_name = f"{label['name']} ({num_messages})" if num_messages > 0 else label['name']
            color = wx.Colour(0, 191, 255) if num_messages > 0 else None
            label_data.append((label_name, color, label['id']))

        return label_data

    except HttpError as error:
        wx.MessageBox(f"An error occurred: {error}", "Error", wx.OK | wx.ICON_ERROR)


def list_messages(service, label_id):
    try:
        response = service.users().messages().list(userId='me', labelIds=[label_id]).execute()
        messages = response.get('messages', [])
        return messages
    except HttpError as error:
        wx.MessageBox(f"An error occurred: {error}", "Error", wx.OK | wx.ICON_ERROR)


def get_message_subject(service, message_id):
    try:
        msg = service.users().messages().get(userId='me', id=message_id).execute()
        headers = msg['payload']['headers']
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'Aucun sujet')
        return subject
    except HttpError as error:
        wx.MessageBox(f"An error occurred: {error}", "Error", wx.OK | wx.ICON_ERROR)


def refresh_labels(event, label_listctrl, service):
    label_listctrl.DeleteAllItems()

    labels = list_labels(service)

    for index, (label_name, label_color, label_id) in enumerate(labels):
        label_listctrl.InsertItem(index, label_name)
        if label_color is not None:
            label_listctrl.SetItemTextColour(index, label_color)
        label_listctrl.SetItemData(index, index)

    label_listctrl.SetColumnWidth(0, wx.LIST_AUTOSIZE)


def refresh_message_list(message_listctrl, label_listctrl, service):
    message_listctrl.DeleteAllItems()

    selected_label_index = label_listctrl.GetFirstSelected()
    if selected_label_index == wx.NOT_FOUND:
        return

    selected_label_name = label_listctrl.GetItemText(selected_label_index)
    selected_label_color = None  # Vous pouvez ajouter la couleur si nécessaire
    selected_label_id = label_listctrl.GetItemData(selected_label_index)

    messages = list_messages(service, selected_label_id)

    for index, message in enumerate(messages):
        subject = get_message_subject(service, message['id'])
        message_listctrl.InsertItem(index, subject)
        message_listctrl.SetItemData(index, index)

    message_listctrl.SetColumnWidth(0, wx.LIST_AUTOSIZE)


def delete_message(event, message_listctrl, label_listctrl, labels, service):
    selected_message_index = message_listctrl.GetFirstSelected()
    if selected_message_index == wx.NOT_FOUND:
        return
    selected_label_index = label_listctrl.GetFirstSelected()
    selected_label_name, selected_label_color, selected_label_id = labels[selected_label_index]
    messages = list_messages(service, selected_label_id)
    selected_message = messages[selected_message_index]
    message_id = selected_message['id']
    try:
        service.users().messages().delete(userId='me', id=message_id).execute()
        wx.MessageBox("Message deleted successfully.", "Message Deleted", wx.OK | wx.ICON_INFORMATION)
        # refresh_message_list(message_listctrl, label_listctrl, service)
        # refresh_labels(event, label_listctrl, service)
    except HttpError as error:
        wx.MessageBox(f"An error occurred while deleting the message: {error}", "Error", wx.OK | wx.ICON_ERROR)


def save_draft(event, service, to, subject_text, content_text):
    subject = subject_text.GetValue()
    content = content_text.GetValue()

    try:
        message = create_message(to, subject, content)
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_draft = {"message": {"raw": encoded_message}}
        service.users().drafts().create(userId="me", body=create_draft).execute()
        wx.MessageBox("Draft saved successfully.", "Draft Saved", wx.OK | wx.ICON_INFORMATION)
    except Exception as e:
        wx.MessageBox(f"An error occurred while saving the draft: {e}", "Error", wx.OK | wx.ICON_ERROR)


def new_message(event, service):
    dialog = wx.Dialog(None, title="New Message", size=(800, 600))
    dialog.Center()

    panel = wx.Panel(dialog)

    to_label = wx.StaticText(panel, label="Recipient:")
    to_text = wx.TextCtrl(panel, size=(600, -1))
    subject_label = wx.StaticText(panel, label="Subject:")
    subject_text = wx.TextCtrl(panel, size=(600, -1))
    content_label = wx.StaticText(panel, label="Content:")
    content_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE, size=(500, 400))

    send_button = wx.Button(panel, label="Send Message")
    save_draft_button = wx.Button(panel, label="Save Draft")

    sizer = wx.FlexGridSizer(cols=2, hgap=5, vgap=5)
    sizer.Add(to_label, 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
    sizer.Add(to_text, 0, wx.EXPAND)
    sizer.Add(subject_label, 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
    sizer.Add(subject_text, 0, wx.EXPAND)
    sizer.Add(content_label, 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
    sizer.Add(content_text, 0, wx.EXPAND)
    sizer.Add(send_button, 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL | wx.TOP, 5)
    sizer.Add(save_draft_button, 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL | wx.TOP, 5)

    panel.SetSizer(sizer)
    sizer.Fit(panel)

    def on_send(event):
        to = to_text.GetValue()
        subject = subject_text.GetValue()
        content = content_text.GetValue()

        try:
            message = create_message(to, subject, content)
            send_message(service, message)
            wx.MessageBox("Message sent successfully.", "Message Sent", wx.OK | wx.ICON_INFORMATION)
            dialog.Close()
        except Exception as e:
            wx.MessageBox(f"An error occurred while sending the message: {e}", "Error", wx.OK | wx.ICON_ERROR)

    send_button.Bind(wx.EVT_BUTTON, on_send)
    save_draft_button.Bind(wx.EVT_BUTTON, lambda event: save_draft(event, service, to_text, subject_text, content_text))

    def on_save_draft(event):
        to = to_text.GetValue()
        subject = subject_text.GetValue()
        content = content_text.GetValue()

        save_draft(event, service, to, subject_text, content_text)

    send_button.Bind(wx.EVT_BUTTON, on_send)
    save_draft_button.Bind(wx.EVT_BUTTON, on_save_draft)

    dialog.ShowModal()


def create_message(to, subject, content):
    message = EmailMessage()
    message.set_content(content)
    message["To"] = to
    message["From"] = "your_email@gmail.com"  # Replace with your email address
    message["Subject"] = subject
    return message


def send_message(service, message):
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    create_message = {"raw": encoded_message}
    service.users().messages().send(userId="me", body=create_message).execute()


def display_labels_and_messages(labels, service):
    global frame

    app = wx.App()
    frame = wx.Frame(None, title="Gmail", size=(1200, 800))

    toolbar = frame.CreateToolBar(style=wx.TB_HORIZONTAL | wx.TB_TEXT)
    toolbar.SetToolBitmapSize(wx.Size(16, 16))

    new_message_icon = wx.ArtProvider.GetBitmap(wx.ART_NEW, wx.ART_TOOLBAR, wx.Size(16, 16))
    tool_new_message = toolbar.AddTool(wx.ID_ANY, "New Message", new_message_icon)
    toolbar.Realize()

    refresh_icon = wx.ArtProvider.GetBitmap(wx.ART_REDO, wx.ART_TOOLBAR, wx.Size(16, 16))
    tool_refresh = toolbar.AddTool(wx.ID_ANY, "Refresh", refresh_icon)
    frame.Bind(wx.EVT_TOOL, refresh_labels, tool_refresh)

    delete_icon = wx.ArtProvider.GetBitmap(wx.ART_DELETE, wx.ART_TOOLBAR, wx.Size(16, 16))
    tool_delete = toolbar.AddTool(wx.ID_ANY, "Delete", delete_icon)

    quit_icon = wx.ArtProvider.GetBitmap(wx.ART_QUIT, wx.ART_TOOLBAR, wx.Size(16, 16))
    tool_quit = toolbar.AddTool(wx.ID_ANY, "Quit", quit_icon)
    toolbar.Realize()

    panel = wx.Panel(frame)

    main_sizer = wx.BoxSizer(wx.HORIZONTAL)

    vertical_splitter = wx.SplitterWindow(panel)

    label_listctrl = wx.ListCtrl(vertical_splitter, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
    label_listctrl.InsertColumn(0, 'Labels', width=200)
    for index, (label_name, label_color, label_id) in enumerate(labels):
        label_listctrl.InsertItem(index, label_name)
        if label_color is not None:
            label_listctrl.SetItemTextColour(index, label_color)
        label_listctrl.SetItemData(index, index)

    horizontal_splitter = wx.SplitterWindow(vertical_splitter)

    message_listctrl = wx.ListCtrl(horizontal_splitter, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
    message_listctrl.InsertColumn(0, 'Mail', width=2540)

    message_content_html = wx.html.HtmlWindow(horizontal_splitter)

    horizontal_splitter.SplitHorizontally(message_listctrl, message_content_html)
    horizontal_splitter.SetSashGravity(0.5)
    horizontal_splitter.SetMinimumPaneSize(200)

    vertical_splitter.SplitVertically(label_listctrl, horizontal_splitter)
    vertical_splitter.SetSashGravity(0.5)
    vertical_splitter.SetMinimumPaneSize(200)

    main_sizer.Add(vertical_splitter, 1, wx.EXPAND | wx.ALL, 0)

    panel.SetSizer(main_sizer)
    frame.Show()

    frame.Bind(wx.EVT_TOOL, lambda event: new_message(event, service), id=tool_new_message.GetId())
    frame.Bind(wx.EVT_TOOL, lambda event: refresh_labels(event, label_listctrl, service), id=tool_refresh.GetId())
    frame.Bind(wx.EVT_TOOL, lambda event: delete_message(event, message_listctrl, label_listctrl, labels, service), id=tool_delete.GetId())
    frame.Bind(wx.EVT_TOOL, close_frame, id=tool_quit.GetId())

    def on_label_selected(event):
        selected_label_index = label_listctrl.GetFirstSelected()
        if selected_label_index == wx.NOT_FOUND:
            return
        selected_label_name, selected_label_color, selected_label_id = labels[selected_label_index]
        messages = list_messages(service, selected_label_id)
        message_listctrl.DeleteAllItems()
        for index, message in enumerate(messages):
            subject = get_message_subject(service, message['id'])
            message_listctrl.InsertItem(index, subject)
            message_listctrl.SetItemData(index, index)

    logging.basicConfig(level=logging.DEBUG)

    def on_message_selected(event):
        try:
            selected_message_index = message_listctrl.GetFirstSelected()
            if selected_message_index == wx.NOT_FOUND:
                return

            selected_label_index = label_listctrl.GetFirstSelected()
            selected_label_name, selected_label_color, selected_label_id = labels[selected_label_index]
            messages = list_messages(service, selected_label_id)
            selected_message = messages[selected_message_index]

            message = service.users().messages().get(userId='me', id=selected_message['id'], format="full").execute()
            payload = message.get('payload', {})
            parts = payload.get('parts', [])

            def extract_html(parts):
                for part in parts:
                    if 'mimeType' in part and part['mimeType'] == 'text/html':
                        if part.get('body') and part['body'].get('data'):
                            data = part['body']['data']
                            html_data = base64.urlsafe_b64decode(data).decode('utf-8')
                            return html_data
                        elif 'data' in part['body']:
                            data = part['body']['data']
                            html_data = base64.urlsafe_b64decode(data).decode('utf-8')
                            return html_data
                        elif 'parts' in part:
                            html_data = extract_html(part['parts'])
                            if html_data:
                                return html_data
                return ''

            html_content = extract_html(parts)

            headers = {header['name']: header['value'] for header in payload.get('headers', [])}
            subject = headers.get('Subject', 'No Subject')
            date_str = headers.get('Date', 'No Date')
            from_email = headers.get('From', 'No Sender')
            to_emails = headers.get('To', 'No Recipient')

            # Afficher la chaîne de date brute
            formatted_date = date_str

            formatted_from = f"From: {from_email}"
            formatted_to = f"To: {to_emails}"

            combined_html = f"""
            <html>
            <head>
                <meta charset="UTF-8">
            </head>
            <body>
                <h1>{subject}</h1>
                <hr>
                <h3>{formatted_date}</h3>
                <h3>{formatted_from}</h3>
                <h3>{formatted_to}</h3>
                <hr>
                {html_content}
            </body>
            </html>
            """

            if 'threadId' in message:
                thread_id = message['threadId']
                thread_messages = service.users().threads().get(userId='me', id=thread_id, format="full").execute()
                replies = thread_messages.get('messages', [])[1:]
                for reply in replies:
                    reply_payload = reply.get('payload', {})
                    reply_parts = reply_payload.get('parts', [])
                    reply_html_content = extract_html(reply_parts)
                    reply_subject = reply_payload.get('subject', 'No Subject')
                    combined_html += f"<hr><h2>Reply: {reply_subject}</h2>{reply_html_content}"

            message_content_html.SetPage(combined_html)

        except Error as error:
            wx.MessageBox(f"An unexpected error occurred: {error}", "Error", wx.OK | wx.ICON_ERROR)

    label_listctrl.Bind(wx.EVT_LIST_ITEM_SELECTED, on_label_selected)
    message_listctrl.Bind(wx.EVT_LIST_ITEM_SELECTED, on_message_selected)

    app.MainLoop()


def main():
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)
    labels = list_labels(service)

    if labels:
        display_labels_and_messages(labels, service)
    else:
        print("No labels found.")


if __name__ == '__main__':
    main()
