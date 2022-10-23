# curl-to-drive [WIP]
A remote uploader that doesn't touch your HDD

This tool takes a curl command only with -H options (since it translates it to python requests) and streams the incoming data to a google drive file.
To do that it uses google drive's api for resumable uploads

`main.py "<curl-command>"`

Feel free to reuse and modify however you want