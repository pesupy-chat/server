class firstrun():
    welcome_message = "Welcome to PesuPy Chat Server Software!"
    keypair_setup = "Setting up Server Keypair..."
    initialize_db = "Setting up Databases for use..."
    security = "For security reasons, enter server launch password again."
    class savedata():
        gui = "Choose a folder for the server to save its data in"
        nogui = "Cannot open file chooser! Enter the path manually:"
        error = "An error occurred"
        write_error = "An error occurred while trying to write server files.\nPlease choose another path"
        not_a_dir = "Please enter path to a folder!"
        creating = "Folder not accessible."
        input_writable = "Please enter a writeable folder path"
        created = "Written Server files successfully."
        created_new = "Created Server folder successfully."
    class passwd():
        explain = "\
         \
        "
        input = "Enter the server's launch password: "
        confirm = "Enter it again to confirm: "
        retry = "Passwords do not match!"