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

Before using GmailManager, ensure you have the following:

- **Python**: Version 3.7 or higher installed on your system.
- **Google Cloud Platform Project**: Have a project set up with the Gmail API enabled.
- **OAuth 2.0 Credentials File**: Download the `credentials.json` file from the Google Cloud Console.
- **Dependencies**: Make sure the following dependencies are installed:

   - `os`: Python standard module for interacting with the operating system.
   - `base64`: Python standard module for encoding and decoding in base64.
   - `google-auth`: Library for Google authentication.
   - `google-auth-oauthlib`: Library for OAuth2 authentication with Google.
   - `google-api-python-client`: Library for using Google APIs in Python.
   - `pytz`: Library for managing timezones in Python.
   - `PyQt5`: Une bibliothèque pour créer des applications de bureau multiplateformes à l'aide de l'interface graphique PyQt5.
   - `email`: Python standard module for email manipulation.

  Make sure to install these dependencies before running your GmailManager script.

- [Google API Client Library for Python](https://github.com/googleapis/google-api-python-client)
- [PyQt](https://riverbankcomputing.com/software/pyqt/intro)


## Installation
1. Clone this repository:
    ```sh
    git clone https://github.com/C0sm0cats/GmailManager.git
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

## GmailManager Screenshot
![GmailManager Screenshot](screenshot.png)

## Contributing
This project is currently a work-in-progress (WIP). Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
