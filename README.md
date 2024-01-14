# QRCode-Server
Reads qr-codes, show the data: this is server side


**This project consists two repositoris** 

* QRCode-Scanner, contains "scanner-side"

* QRCode-Server, contains "server-side" (this repo)

![Selection_611](https://github.com/sepdijono/QRCode-Server/assets/54463742/2a717161-fa15-44e7-9da4-eb9e8ef2fff6)

QRCode-scanner use OpenCV2 with GPU support, all scanned qr-codes will be shown in a box with respective data on it. There is only two qr-code types: 
1. Registered qr-code will shown the data (username, full name, address, scanned location)
2. Unregistered qr-code will be appeared as "Tidak terdaftar"

Installation:
1. Install postgresql please refers the postgresql official website
2. Build opencv support gpu using cmake / cmake-gui
3. Install all dependencies using pip install -r requirements.txt
4. This project implement FastAPI, PyJwt & Alembic database versioning / migration tools for python, please refers the respective official website
5. Don't forget to copy env-example to .env
   
However, unfortunately this is just prototype so it comes as is. 

Oke thats all hope you find something useful

Regards: pyy
