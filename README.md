# GmailManager

Manage your Gmail inbox effortlessly with GmailManager, a powerful Python script to organize, delete, and draft emails directly from your desktop.

## Description
GmailManager is a desktop application written in Python that allows you to manage your Gmail inbox. This application uses the Gmail API for authentication, displaying labels, managing messages (reading, deleting, drafts), and composing new emails.

## Features
- Display Gmail labels
- Display messages by label
- Read messages
- Delete messages
- Save drafts
- Compose and send new messages

## Prerequisites
- Python 3.7 or higher
- [Google API Client Library for Python](https://github.com/googleapis/google-api-python-client)
- [wxPython](https://www.wxpython.org/)

## Installation
1. Clone this repository:
    ```sh
    git clone https://github.com/your-username/GmailManager.git
    cd GmailManager
    ```

2. Configure the Gmail API:
    - Follow the instructions to create OAuth 2.0 credentials for your project [here](https://developers.google.com/identity/protocols/oauth2) and download the `credentials.json` file.
    - Place `credentials.json` in the project directory.

## Usage
1. Run the main script:
    ```sh
    python gmailmanager.py
    ```

2. A browser window will open asking you to sign in to your Gmail account and authorize access for the application.

3. Once authenticated, the application will display your Gmail labels and messages.

## Contributing
This project is currently a work-in-progress (WIP). Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
