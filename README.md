# Communications LTD (Safe version)

This project presents a demo website of an imaginary company named 'Communications LTD'.


According to the requirements, it supports several features:
1. Register - Create a new account with a username, e-mail and password.
2. Change Password - Change the password
3. Login - Log in with username and password. Basic Rate limiting and password checks implemented.
4. Basic Client Management System - View a list of clients, add new ones.
5. 'Forget Password' - sends an E-mail to reset the password


We will review installation and usage first, and then review the main files and security mechanisms implemented in this project to prevent attacks such as SQL Injections and Stored XSS.


1. Installation & Usage
Currently this project is not shipped with Docker, so follow these steps.
First, Download the project from GitHub. Then make sure you have PostgreSQL installed and running. 
Then manage the configurations in `config.py` and create a new `
