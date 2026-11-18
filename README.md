# Cloud-Based File Storage and Sharing Platform

A beginner-friendly Flask + SQLite project implementing the requirements in the supplied project brief.

## Features
- Admin and registered-user roles
- Register, login and logout with hashed passwords
- Upload, download, preview and organize files in folders
- File metadata (name, size, MIME type, upload/update time) and version field
- Share files with registered users using view/edit permission labels
- Storage quota tracking and admin quota management
- Storage utilization, file upload, shared files and user activity reports
- Activity logs for login, upload, download, preview, delete, share and folder actions
- Responsive dashboard and navigation

## Requirements
- Python 3.9 or newer
- pip

## Run on Windows
1. Extract the ZIP.
2. Open the extracted folder in VS Code.
3. Open Terminal in that folder.
4. Create a virtual environment:
   ```bash
   py -m venv venv
   venv\Scripts\activate
   ```
5. Install packages:
   ```bash
   pip install -r requirements.txt
   ```
6. Start the application:
   ```bash
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser.

## Demo accounts
- Admin: `admin` / `Admin@123`
- Registered user: `demo` / `User@123`

Change these passwords before using the app outside a local demonstration. Set a strong `SECRET_KEY` environment variable for deployment.

## Project structure
```text
cloud_file_storage_platform/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── files.html
│   ├── shared.html
│   ├── share.html
│   ├── reports.html
│   ├── admin_users.html
│   └── error.html
├── static/
│   └── style.css
└── storage/              # uploaded files are stored here
```

## Notes / extension ideas
- This is a local academic demonstration, not a production cloud storage service.
- The `edit` share permission is recorded and displayed; the current interface supports preview/download for shared files. Add collaborative editing or shared-file replacement if required.
- A file's version field is initialized to 1. Version history can be extended by storing previous physical files in a separate `file_versions` table.
- For production, add CSRF protection, antivirus scanning, file-type validation, object storage (S3/Azure/GCS), HTTPS, rate limiting and stronger authorization checks.
