class firstrun():
    setting_not_found = "Could not determine server's {0}"
    empty_config = "Server configuration is empty. Deleting..."
    ft_question = "Is this the first time you are running the server?"
    config_not_found = "Configuration file not found!"
    exec = "Server will now run its configuration process"
    fix_missing = "Please enter the Server's {0}"
    welcome_message = "Welcome to the Account System Demonstration Backend"
    setup_server_dir = "Please enter the path to a folder where the server can store its files"
    keypair_setup = "Setting up Server Keypair..."
    initialize_db = "Setting up Databases for use..."
    security = "For security reasons, enter server launch password again."
    exit = "Server will now exit. Please run it again!"
    listenaddr = "Enter Server Listen Address: "
    listenport = "Enter Server Listen Port: "
class savedata():
    gui = "Opening file chooser dialog..."
    nogui = "Cannot open file chooser! Enter the path manually:"
    error = "An error occurred"
    write_error = "An error occurred while trying to write server files.\nPlease choose another path"
    not_a_dir = "Please enter path to a folder!"
    creating = "Folder not accessible."
    input_writable = "Please enter a writeable folder path"
    created = "Written Server files successfully."
    created_new = "Created Server folder successfully."
    data_exists = "Previous Installation Detected! Please delete the files or choose another folder."
class database():
    host = 'Enter MySQL/MariaDB Server IP Address: '
    port = 'Enter MySQL/MariaDB Server Port (leave blank for 3306): '
    user = 'Enter Username of user with CREATE privilege: '
    passwd = 'Enter Password of the user: '
    creds_not_found = "Could not find database credentials. Rerunning server configuration process"

class password():
    explain = "The server's 'Launch Password' is used to encrypt credentials.\n\
The server will not launch without it."
    input = "Enter the server's launch password: "
    confirm = "Enter it again to confirm: "
    retry = "Passwords do not match!"

class log():
    class tags():
        info = '[INFO] '
        warn = '[WARN] '
        error = '[ERR] '
    class conn():
        disconnected = "Client {0} disconnected due to:\n\t{1}"        
    server_start = "Server starting from path {0}...."