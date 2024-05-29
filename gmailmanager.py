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
import json
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


def refresh_message_list(message_listctrl, label_listctrl, service, labels):
    message_listctrl.DeleteAllItems()

    selected_label_index = label_listctrl.GetFirstSelected()
    if selected_label_index == wx.NOT_FOUND:
        return
    selected_label_name, selected_label_color, selected_label_id = labels[selected_label_index]
    selected_label_id = str(selected_label_id)  # Conversion de l'ID en chaîne de caractères

    messages = list_messages(service, selected_label_id)

    for index, message in enumerate(messages):
        subject = get_message_subject(service, message['id'])
        message_listctrl.InsertItem(index, subject)
        message_listctrl.SetItemData(index, index)

    message_listctrl.SetColumnWidth(0, wx.LIST_AUTOSIZE)


def delete_message(event, message_listctrl, label_listctrl, labels, service, on_label_selected):
    selected_message_index = message_listctrl.GetFirstSelected()
    if selected_message_index == wx.NOT_FOUND:
        return
    selected_label_index = label_listctrl.GetFirstSelected()
    selected_label_name, selected_label_color, selected_label_id = labels[selected_label_index]
    messages = list_messages(service, selected_label_id)
    if selected_message_index >= len(messages):
        return
    message_id = messages[selected_message_index]['id']
    try:
        service.users().messages().delete(userId='me', id=message_id).execute()
        wx.MessageBox("Message deleted successfully.", "Message Deleted", wx.OK | wx.ICON_INFORMATION)

        # Refresh the label list
        refresh_labels(event, label_listctrl, service)

        # Re-select the active label
        label_listctrl.Select(selected_label_index)

        # Select the first message in the list for the active label
        on_label_selected(event)
        message_listctrl.Select(0)

    except HttpError as error:
        wx.MessageBox(f"An error occurred while deleting the message: {error}", "Error", wx.OK | wx.ICON_ERROR)


def save_draft(event, service, to_text, subject_text, content_text, label_listctrl, message_listctrl, labels):
    subject = subject_text.GetValue()
    content = content_text.GetValue()

    try:
        message = create_message(to_text.GetValue(), subject, content)
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_draft = {"message": {"raw": encoded_message}}
        service.users().drafts().create(userId="me", body=create_draft).execute()
        wx.MessageBox("Draft saved successfully.", "Draft Saved", wx.OK | wx.ICON_INFORMATION)

        # Refresh the labels and messages
        refresh_labels(event, label_listctrl, service)

        # Find the index of the "DRAFT" label
        draft_label_index = next((index for index, (label_name, _, label_id) in enumerate(labels) if label_id == 'DRAFT'), None)
        if draft_label_index is not None:
            label_listctrl.Select(draft_label_index)
            refresh_message_list(message_listctrl, label_listctrl, service, labels)

    except Exception as e:
        wx.MessageBox(f"An error occurred while saving the draft: {e}", "Error", wx.OK | wx.ICON_ERROR)


def new_message(event, service, label_listctrl, message_listctrl, labels):
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
            send_message(service, message, label_listctrl, message_listctrl, labels)
            wx.MessageBox("Message sent successfully.", "Message Sent", wx.OK | wx.ICON_INFORMATION)
            dialog.Close()
        except Exception as e:
            wx.MessageBox(f"An error occurred while sending the message: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def on_save_draft(event):
        to = to_text.GetValue()
        subject = subject_text.GetValue()
        content = content_text.GetValue()

        save_draft(event, service, to, subject_text, content_text, label_listctrl, message_listctrl, labels)

    send_button.Bind(wx.EVT_BUTTON, on_send)
    save_draft_button.Bind(wx.EVT_BUTTON, lambda event: save_draft(event, service, to_text, subject_text, content_text, label_listctrl, message_listctrl, labels))

    dialog.ShowModal()


def create_message(to, subject, content):
    message = EmailMessage()
    message.set_content(content)
    message["To"] = to
    message["From"] = "your_email@gmail.com"  # Replace with your email address
    message["Subject"] = subject
    return message


def send_message(service, message, label_listctrl, message_listctrl, labels):
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    create_message = {"raw": encoded_message}
    service.users().messages().send(userId="me", body=create_message).execute()
    wx.MessageBox("Message sent successfully.", "Message Sent", wx.OK | wx.ICON_INFORMATION)

    # Refresh the labels and messages
    refresh_labels(None, label_listctrl, service)

    # Find the index of the "SENT" label
    sent_label_index = next((index for index, (label_name, _, label_id) in enumerate(labels) if label_id == 'SENT'), None)
    if sent_label_index is not None:
        label_listctrl.Select(sent_label_index)
        refresh_message_list(message_listctrl, label_listctrl, service, labels)


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

    frame.Bind(wx.EVT_TOOL, lambda event: new_message(event, service, label_listctrl, message_listctrl, labels), id=tool_new_message.GetId())
    frame.Bind(wx.EVT_TOOL, lambda event: refresh_labels(event, label_listctrl, service), id=tool_refresh.GetId())
    frame.Bind(wx.EVT_TOOL, lambda event: delete_message(event, message_listctrl, label_listctrl, labels, service, on_label_selected), id=tool_delete.GetId())
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
        message_listctrl.SetColumnWidth(0, wx.LIST_AUTOSIZE)

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
            print(json.dumps(service.users().messages().get(userId='me', id=selected_message['id'], format="full").execute(), indent=2))
            payload = message.get('payload', {})
            parts = payload.get('parts', [])

            def extract_data(items):
                result = ""
                for item in items:
                    if 'body' in item and item['body']:
                        if 'data' in item['body']:
                            data = item['body']['data']
                            result += decode_base64(data).decode("utf-8")
                        elif 'attachmentId' in item['body']:
                            attachment_id = item['body']['attachmentId']
                            attachment = service.users().messages().attachments().get(userId='me', messageId=msg_id, id=attachment_id).execute()
                            data = attachment['data']
                            result += decode_base64(data).decode("utf-8")
                    elif 'parts' in item and item['parts']:
                        if 'mimeType' in item and item["mimeType"] == "multipart/alternative":
                            result += extract_data(item['parts'])
                        elif 'mimeType' in item and item["mimeType"] == "multipart/mixed":
                            for sub_item in item['parts']:
                                if 'mimeType' in sub_item and sub_item['mimeType'] != "multipart/*":
                                    result += extract_data([sub_item])
                                else:
                                    result += extract_data(sub_item['parts'])
                        else:
                            result += extract_data(item['parts'])
                return result

            def find_matching_part(parts, mime_type, max_depth, current_depth=0):
                matching_part = None

                for part in parts:
                    if 'mimeType' in part and part['mimeType'] == mime_type:
                        return part

                    if 'parts' in part and current_depth < max_depth:
                        matched_part = find_matching_part(part['parts'], mime_type, max_depth, current_depth=current_depth+1)
                        if matched_part:
                            matching_part = matched_part

                return matching_part

            def extract_html(parts, max_depth=3):
                matching_part = find_matching_part(parts, 'text/html', max_depth)
                if not matching_part:
                    return ""

                if 'body' in matching_part and matching_part['body']:
                    if 'data' in matching_part['body']:
                        data = matching_part['body']['data']
                        html_data = base64.urlsafe_b64decode(data).decode('utf-8')
                        return html_data

                return ""

            def decode_base64(data):
                missing_padding = 4 - len(data) % 4
                if missing_padding:
                    data += '=' * missing_padding
                return base64.urlsafe_b64decode(data)

            if 'text/html' in [part.get('mimeType') for part in parts]:
                content = extract_html([payload])
            else:
                content = extract_data([payload])

            headers = {header['name']: header['value'] for header in payload.get('headers', [])}
            subject = headers.get('Subject', 'No Subject')
            date_str = headers.get('Date', 'No Date')
            from_email = headers.get('From', 'No Sender')
            to_emails = headers.get('To', 'No Recipient')

            # Display raw date string
            formatted_date = date_str

            formatted_from = f"From: {from_email}"
            formatted_to = f"To: {to_emails}"

            combined_html = f"""\
            <html>\
            <head>\
                <meta charset="UTF-8">\
            </head>\
            <body>\
                <h1>{subject}</h1>\
                <hr />\
                <h3>{formatted_date}</h3>\
                <h3>{formatted_from}</h3>\
                <h3>{formatted_to}</h3>\
                <hr />\
                {content}\
            </body>\
            </html>
            """

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
