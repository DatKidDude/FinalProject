"""This application allows the user to store website information in an sqlite database. The user creates an account
and then is able to log into the main part of the application."""

import tkinter as tk
import sqlite3
from tkinter import messagebox
from tkinter import *
import random
from tkinter import ttk
import webbrowser

# Creating the login window
root = tk.Tk()
root.title("Login")
root.geometry("800x500+600+300")
root.configure(bg="#F3F8F6")
root.resizable(False, False)

# Creating the Database
conn = sqlite3.connect("passvault.db")
c = conn.cursor()

# Creating the table and setting password to unique
c.execute("""CREATE TABLE IF NOT EXISTS accountData (
            acct_name text,
            acct_password text not null unique
            )""")

# Creating a seperate table for the user's entry data
c.execute("""CREATE TABLE IF NOT EXISTS userData (
            url_name text,
            username text,
            password text
            )""")


# Commit changes
conn.commit()
# Close connection
conn.close()


def get_info(acct_name, acct_password, confirm_acct_password, new):
    """Stores information for the user account"""
    # Connect to database
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()
    # Checking the accountData table to verify if a user already exists
    c.execute("SELECT * FROM accountData WHERE acct_name=? and "
              "acct_password=?", (acct_name.get(), acct_password.get()))
    # Records are acct_name and acct_password in accountData table
    records = c.fetchall()
    # Checks if user record is already in the database
    if records:
        messagebox.showinfo("Alert", "Password already taken.")
        destroy_acct(new)
        account_window()
    elif len(acct_password.get()) <= 7:
        messagebox.showinfo("Alert", "Password must be at least 8 characters "
                                     "long.")
        destroy_acct(new)
        account_window()
    elif acct_password.get() != confirm_acct_password.get():
        messagebox.showinfo("Alert", "Passwords do not match")
        destroy_acct(new)
        account_window()
    else:
        # Using try-except because if a different name tries to log in with an already taken password you get an error
        try:
            c.execute(
                "INSERT INTO accountData VALUES (:acct_name, :acct_password)",
                {
                    "acct_name": acct_name.get(),
                    "acct_password": acct_password.get()
                }
            )
            # Commit changes
            conn.commit()
            # Close connection
            conn.close()
            # Message box
            messagebox.showinfo("Success!", "Account Added in Database")
            destroy_acct(new)
        except sqlite3.IntegrityError:
            messagebox.showinfo("Alert!", "Password already taken")
            destroy_acct(new)
            account_window()

def account_window():
    """Creates the Create Account window"""
    new = tk.Toplevel(root)
    new.title("Create Account")
    new.geometry("700x500+650+300")
    new.configure(bg="#6D7672")
    new.resizable(False, False)

    # Creating Label Frame
    label_frame = tk.LabelFrame(new, bg="#F3F8F6")
    label_frame.place(relx=0.1, rely=0.1, relheight=0.8, relwidth=0.8)

    # Creating Labels
    create_account = tk.Label(label_frame, bg="#F3F8F6", fg="#3CB98F", text="Create " \
                                   "Account",
                              font=("Helvetica", 30, "bold"))
    create_account.place(relx=0.5, rely=0.07, anchor="center")

    # Creating Entry Boxes
    # Stores account name
    acct_name = tk.Entry(label_frame, width=40, fg="black", border=0, bg="#F3F8F6", font=("Times New Roman", 13))
    acct_name.place(relx=0.1, rely=0.2)
    acct_name.insert(0, "Username/Email")
    acct_name.focus()
    # Stores the account password
    acct_password = tk.Entry(label_frame, width=40, fg="black", border=0, bg="#F3F8F6", font=("Times New Roman", 13))
    acct_password.place(relx=0.1, rely=0.35)
    acct_password.insert(0, "Password (Must be at least 8 characters long)")
    # Validates account password
    confirm_acct_password = tk.Entry(label_frame, width=40, fg="black", border=0, bg="#F3F8F6", font=("Times New Roman", 13))
    confirm_acct_password.place(relx=0.1, rely=0.5)
    confirm_acct_password.insert(0, "Re-enter password")

    # Creating entry box lines
    acct_name_line = tk.Frame(label_frame, width=370, height=1, bg="black")
    acct_name_line.place(relx=0.1, rely=0.26)
    acct_password_line = tk.Frame(label_frame, width=370, height=1, bg="black")
    acct_password_line.place(relx=0.1, rely=0.41)
    confirm_acct_line = tk.Frame(label_frame, width=370, height=1, bg="black")
    confirm_acct_line.place(relx=0.1, rely=0.56)

    # Creating Buttons
    register_btn = tk.Button(label_frame, text="Register", width=40,
                             bg="#3CB98F", pady=5, command=lambda: get_info(
            acct_name, acct_password, confirm_acct_password, new))
    register_btn.place(relx=0.2, rely=0.7)

    exit_btn = tk.Button(label_frame, text="Back to login screen", width=40,
                         bg="#3CB98F", pady=5, command=lambda: new.destroy())
    exit_btn.place(relx=0.2, rely=0.85)

def destroy_acct(new):
    """Closes the account window"""
    new.destroy()


def login(acct_name, acct_pass):
    """Checks if user exists in database then opens app window"""
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()

    c.execute("SELECT * FROM accountData WHERE acct_name=? and "
              "acct_password=?", (acct_name.get(), acct_pass.get()))
    row = c.fetchone()
    # Checking if the user exists in the database
    if row:
        root.destroy()
        appWindow()
    else:
        messagebox.showinfo("Alert", "Wrong username or password")
        acct_name.delete(0, END)
        acct_pass.delete(0, END)
        acct_name.focus()
        acct_name.insert(0, "Username/Email")
        acct_pass.insert(0, "Password")
        acct_pass.config(show="")

    # Commit changes
    conn.commit()
    # Closes connection
    conn.close()

def appWindow():
    """Creating a separate window for app"""
    global update_entry, delete_entry
    app = tk.Tk()
    app.title("PassVault")
    app.geometry("800x500+600+300")
    app.resizable(False, False)
    app.configure(bg="#F3F8F6")
    r = IntVar()

    # Placing image logo
    img2 = tk.PhotoImage(file="blue_lock.png")
    img2_label = tk.Label(app, image=img2, bg="#F3F8F6").place(x=20, y=50) # x=50, y=90


    # Creating app window frame
    app_frame = tk.Frame(app, width=400, height=500, bg="#F3F8F6")
    app_frame.place(x=400)

    # Creating the labels
    url_name = tk.Label(app_frame, text="Website Name:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    url_name.place(y=15)
    username_app = tk.Label(app_frame, text="Username/Email ID:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    username_app.place(y=70)
    password_app = tk.Label(app_frame, text="Password:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    password_app.place(y=125)
    update_label = tk.Label(app_frame, text="<-- Use ID #", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    update_label.place(x=220, y=300)
    delete_label = tk.Label(app_frame, text="<-- Use ID #", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    delete_label.place(x=220, y=350)

    # Creating the entry boxes
    # Stores the website name
    url_name = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    url_name.place(y=40)
    # Stores the username
    username_app = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    username_app.place(y=95)
    # Stores the password
    password_app = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    password_app.place(y=150)
    # Stores the record ID number
    update_entry = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=10, font=("Helvetica", 12), bd=2)
    update_entry.place(x=120, y=303, height=25)
    # Stores the record ID number
    delete_entry = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=10, font=("Helvetica", 12), bd=2)
    delete_entry.place(x=120, y=353, height=25)
    # Stores the website name
    web_entry = tk.Entry(app_frame, bg="#F3F8F6", fg="black", width=25, font=("Helvetica", 12), bd=2)
    web_entry.place(x=120, y=400, height=28)

    # Creating radio buttons
    low = tk.Radiobutton(app_frame, text="Low", variable=r, value=8, bg="#F3F8F6", font=("Helvetica", 12))
    low.place(y=180)
    medium = tk.Radiobutton(app_frame, text="Medium", variable=r, value=10, bg="#F3F8F6", font=("Helvetica", 12))
    medium.place(x=80, y=180)
    strong = tk.Radiobutton(app_frame, text="Strong", variable=r, value=12, bg="#F3F8F6", font=("Helvetica", 12))
    strong.place(x=180, y=180)

    # Creating app buttons
    global update_record, delete_record
    pass_generate = tk.Button(app_frame, text="Generate Password", bg="#36CBE6", pady=1, font=("Helvetica", 9),
                              command=lambda: password_generator(r.get(), password_app))
    pass_generate.place(x=277, y=147)
    add_record = tk.Button(app_frame, text="Add Record", bg="#36CBE6", pady=2, font=("Helvetica", 11), width=30,
                           command=lambda: save_data(url_name, username_app, password_app))
    add_record.place(y=230)
    show_record = tk.Button(app_frame, text="Show Records", bg="#36CBE6", pady=3, font=("Helvetica", 9), width=14,
                            command=lambda: show_records(app))
    show_record.place(x=287, y=230)
    update_record = tk.Button(app_frame, text="Update Record", bg="#36CBE6", pady=3, font=("Helvetica", 9), width=14,
                              command=lambda: update(app) if update_entry.get() != "" else messagebox.showinfo(
                                  "Alert!", "Please enter ID number"))
    update_record.place(y=300)
    delete_record = tk.Button(app_frame, text="Delete Record", bg="#36CBE6", pady=3, font=("Helvetica", 9), width=14,
                              command=lambda: delete_records())
    delete_record.place(y=350)
    web = tk.Button(app_frame, text="Go to website", bg="#36CBE6", pady=3, font=("Helvetica", 9), width=14,
                    command=lambda: website(web_entry))
    web.place(y=400)
    log_out = tk.Button(app_frame, text="Log out", bg="#36CBE6", pady=3, font=("Helvetica", 9), width=14,
                        command=lambda: app.destroy())
    log_out.place(x=150, y=450)


    app.mainloop()


def save_data(url_name, username, password):
    """Submitting user information to user data table."""

    # Connecting to database
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()
    # Checking to see if entry boxes aren't empty and the password is longer than 7 characters
    if url_name.get() == "" or username.get() == "" or password.get() == "":
        messagebox.showinfo("Alert!", "Please fill in any empty boxes.")
    elif len(password.get()) >= 8:
        c.execute("INSERT INTO userData VALUES (:url_name, :username, :password)",
                  {
                      "url_name": url_name.get(),
                      "username": username.get(),
                      "password": password.get()
                      }
                  )
        # Committ changes
        conn.commit()
        # Close connection
        conn.close()
        messagebox.showinfo("Success!", "Record added to database.")
        url_name.delete(0, "end")
        username.delete(0, "end")
        password.delete(0, "end")
    else:
        messagebox.showinfo("Alert!", "Password must be at least 8 characters long.")
        password.delete(0, "end")


def show_records(app):
    """Display the saved records in new window."""
    rec_window = tk.Toplevel(app)
    rec_window.title("Records")
    rec_window.geometry("800x500+600+300")
    rec_window.resizable(False,False)

    # Creating database
    conn = sqlite3.connect("passvault.db")

    c = conn.cursor()

    c.execute("SELECT *, oid FROM userData")
    records = c.fetchall()

    # Commit changes
    conn.commit()
    # Close connection
    conn.close()

    # Creating Frame
    rec_frame = tk.Frame(rec_window, width=800, height=75, bg="#36CBE6", highlightbackground="black",
                         highlightthickness=2)
    rec_frame.pack()

    # Creating Labels
    rec_label = tk.Label(rec_frame, width=7, text="Records", font=("Helvetica", 40), bg="#36CBE6")
    rec_label.place(x=400, anchor="n")

    # Creating Main Frame
    main_frame = tk.Frame(rec_window, bg="#E1E0E0", width=800, height=425)
    main_frame.place(y=75)

    # Creating Canvas
    my_canvas = tk.Canvas(main_frame, bg="#E1E0E0", width=800, height=425)
    my_canvas.place(y=1)

    # Creating Scrollbar
    scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    scrollbar.place(relx=0.98, relheight=1)

    # Configure Canvas
    my_canvas.configure(yscrollcommand=scrollbar.set)
    my_canvas.bind("<Configure>", lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    # Creating another frame inside canvas
    second_frame = tk.Frame(my_canvas, bg="#E1E0E0")

    # Add new frame to a window in a canvas
    my_canvas.create_window((0,0), window=second_frame, anchor="nw")

    # Creating database output
    user_record = ""
    for record in records:
        user_record += "ID: " + str(record[3]) + " / " + str(record[0]) + " / " + str(record[1]) + " / " + str(record[
                                                                                                                 2]) \
                       + "\n" + "\n"

    # Create Output Label
    myLabel = tk.Label(second_frame, text=user_record, font=("Helvetica", 12), justify=LEFT, bg="#E1E0E0")
    myLabel.pack()

    # Create Return Button
    r_button = tk.Button(rec_window, text="Return to previous screen", bg="#36CBE6", width=20, pady=3,
                         font=("Helvetica", 10), command=lambda: rec_window.destroy()) #record_button(rec_window)
    r_button.place(relx=0.4, rely=0.9)



def password_generator(value, password_app):
    """Creating a random password and stores it as a string."""
    password_app.delete(0, END)
    my_pass = ""
    for i in range(value):
        my_pass += chr(random.randint(33, 126))
    password_app.insert(0, my_pass)

def pass_enter(e):
    """Erasing entry word in the password entry box on login screen and replacing it with asterisks."""
    password.delete(0, "end")
    password.config(show="*")

def update(app):
    """Updates database using oid number"""
    editor = tk.Toplevel(app)
    editor.title("Update Record")
    editor.geometry("500x500+800+300")
    editor.resizable(False, False)
    r = IntVar()

    # Creating Frame
    e_frame1 = tk.Frame(editor, bg="#36CBE6", width=500, height=100, highlightthickness=2,
                        highlightbackground="black")
    e_frame1.pack()
    e_frame2 = tk.Frame(editor, bg="#F3F8F6", width=500, height=400)
    e_frame2.pack()

    # Creating Labels
    update_lbl = tk.Label(e_frame1, bg="#36CBE6", text="Update Records", font=("Helvetica", 35, "bold"), anchor=CENTER)
    update_lbl.place(relx=0.15, rely=0.2)
    url_editor = tk.Label(e_frame2, text="Website Name:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    url_editor.place(x=15, y=15)
    username_editor = tk.Label(e_frame2, text="Username/Email ID:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    username_editor.place(x=15, y=70)
    password_editor = tk.Label(e_frame2, text="Password:", font=("Helvetica", 14), bg="#F3F8F6", fg="gray")
    password_editor.place(x=15, y=125)

    # Creating the entry boxes
    # Stores website name
    url_editor_entry = tk.Entry(e_frame2, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    url_editor_entry.place(x=20, y=40)
    # Stores username
    username_editor_entry = tk.Entry(e_frame2, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    username_editor_entry.place(x=20, y=95)
    # Stores password
    password_app_entry = tk.Entry(e_frame2, bg="#F3F8F6", fg="black", width=30, font=("Helvetica", 12))
    password_app_entry.place(x=20, y=150)

    # Creating Radio Buttons
    low_1 = tk.Radiobutton(e_frame2, text="Low", variable=r, value=8, bg="#F3F8F6", font=("Helvetica", 12))
    low_1.place(x=20, y=180)
    medium_1 = tk.Radiobutton(e_frame2, text="Medium", variable=r, value=10, bg="#F3F8F6", font=("Helvetica", 12))
    medium_1.place(x=95, y=180)
    strong_1 = tk.Radiobutton(e_frame2, text="Strong", variable=r, value=12, bg="#F3F8F6", font=("Helvetica", 12))
    strong_1.place(x=200, y=180)

    # Creating Buttons
    pass_generate = tk.Button(e_frame2, text="Generate Password", bg="#36CBE6", pady=1, font=("Helvetica", 9),
                              command=lambda: password_generator(r.get(), password_app_entry))  # 36CBE6
    pass_generate.place(x=300, y=147)
    save_record = tk.Button(e_frame2, text="Submit Record", bg="#36CBE6", pady=3, font=("Helvetica", 12), width=20,
                            command=lambda: update_sql(url_editor_entry, username_editor_entry, password_app_entry,
                                                       update_entry))
    save_record.place(x=50, y=240)
    exit_btn = tk.Button(e_frame2, text="Return to previous screen", bg="#36CBE6", pady=3, font=("Helvetica", 12),
                         width=20, command=lambda: editor.destroy())
    exit_btn.place(x=50, y=300)

    # Displaying requested record in the entry boxes
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()

    record_id = update_entry.get()
    c.execute("SELECT * FROM userData WHERE oid = " + record_id)

    # Checking the userData table for the ID number of a specific record to display
    records = c.fetchall()
    if records:
        for record in records:
            url_editor_entry.insert(0, record[0])
            username_editor_entry.insert(0, record[1])
            password_app_entry.insert(0, record[2])

        conn.commit()

        conn.close()
    else:
        editor.destroy()
        update_entry.delete(0, END)
        messagebox.showinfo("Alert!", "ID number not in records")

    editor.mainloop()

def update_sql(url_editor_entry, username_editor_entry, password_app_entry, update_entry):
    """Saves updated records"""
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()

    # Checking to make sure entry boxes aren't empty and password is longer than 7 characters
    if url_editor_entry.get() != "" and username_editor_entry.get() != "" and password_app_entry.get() != "" and len(
            password_app_entry.get()) >= 8:
        c.execute("""UPDATE userData SET
                url_name = :url_name,
                username = :username,
                password = :password

                WHERE oid = :oid""",

                  { "url_name": url_editor_entry.get(),
                    "username": username_editor_entry.get(),
                    "password": password_app_entry.get(),
                    "oid": update_entry.get()
                 }
                  )

        conn.commit()

        conn.close()
        messagebox.showinfo("Info", "Record Updated in Database!")
        update_entry.delete(0, END)
    else:
        messagebox.showinfo("Alert!", "Please fill in any empty boxes and make sure password is at least 8 "
                                      "characters.")

def delete_records():
    """Deleting Records"""
    # Creating the database
    conn = sqlite3.connect("passvault.db")
    c = conn.cursor()
    c.execute("""SELECT oid FROM userData WHERE oid = :oid """,
                       {
                           "oid": delete_entry.get()
                       })
    exists = c.fetchall()
    erase = delete_entry.get()
    # Checking if the ID number exists and deletes the record
    if not exists or erase == "":
        messagebox.showinfo("Alert!", "ID number does not exist.")
        delete_entry.delete(0, END)
    else:
        erase = delete_entry.get()
        c.execute("DELETE FROM userData where oid = " + delete_entry.get())
        delete_entry.delete(0, END)
        messagebox.showinfo("Alert", "Record %s deleted successfully" % erase)

        conn.commit()

        conn.close()

def website(web_entry):
    """Opens up the web browser."""
    if web_entry.get() == "":
        messagebox.showinfo("Alert!", "Please fill in entry box")
    else:
        # Inserts www. if user does not explicitly type it out
        if "www." in web_entry.get():
            webbrowser.open("https://" + web_entry.get())
            web_entry.delete(0, END)
        else:
            webbrowser.open("https://www." + web_entry.get())
            web_entry.delete(0, END)


# Placing image logo
img = tk.PhotoImage(file="login3.png")
img_label = tk.Label(root, image=img, bg="#F3F8F6").place(x=50, y=90)

# Creating the frames
login_frame = tk.Frame(root, width=350, height=350, bg="#F3F8F6")
login_frame.place(x=420, y=92)
username_line = tk.Frame(login_frame, width=295, height=1, bg="black")
username_line.place(x=25, y=101)
password_line = tk.Frame(login_frame, width=295, height=1, bg="black")
password_line.place(x=25, y=172)

# Creating the labels
sign_in_label = tk.Label(login_frame, text="Sign In", fg="#3CB98F", bg="#F3F8F6", font=("Helvetica", 23, "bold"))
sign_in_label.place(x=120, y=5)
account_label = tk.Label(login_frame, text="Create an account?", fg="black", bg="#F3F8F6",
                         font=("Times New Roman", 11))
account_label.place(x=80, y=320)

# Creating the entry boxes
# Stores the account username
username = tk.Entry(login_frame, width=30, fg="black", border=0, bg="#F3F8F6", font=("Times New Roman", 13))
username.place(x=30, y=80)
username.insert(0, "Username/Email")
username.focus()
# Stores account password
password = tk.Entry(login_frame, width=30, fg="black", border=0, bg="#F3F8F6", font=("Times New Roman", 13))
password.place(x=30, y=150)
password.insert(0, "Password")
password.bind("<FocusIn>", pass_enter)

# Creating buttons
sign_in_btn = tk.Button(login_frame, text="Sign In", bg="#3CB98F", width=35, pady=5, command=lambda: login(username, password))

sign_in_btn.place(x=45, y=200)
sign_up_btn = tk.Button(login_frame, border=0, width=9, fg="#0000EE", bg="#F3F8F6",
                        cursor="hand2", text="Sign Up", command=account_window)
sign_up_btn.place(x=200, y=320)
exit_btn = tk.Button(login_frame, text="Exit", bg="#3CB98F", width=35, pady=5, command=lambda: root.destroy())
exit_btn.place(x=45, y=255)

def main():
    """Starts up the application."""
    root.mainloop()

if __name__ == "__main__":
    main()

