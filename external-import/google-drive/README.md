# OpenCTI Google Drive Connector

Create reports based on a Google drive folder.

To configure the Service Account:

1. On the Google Cloud Dashboard dashboard start by creating new project.
2. Enable the google Drive API for the project
3. Create the credentials by selecting the service account for the project (give editor access to it)
4. Select newly created service account and create new keys 
5. Download the keys in JSON wich match connector configuration
6. Inside Google Drive, share the folder with the service account email address

Those steps with screenshots can be found at the beginning of [this blog post](https://dev.to/binaryibex/python-and-google-drive-how-to-list-and-create-files-and-folders-2023-2nmm).