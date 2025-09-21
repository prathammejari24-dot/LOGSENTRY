import re
import pyfiglet
import sys
from colorama import init, Fore, Style
from collections import Counter

# Initialize colorama
init(autoreset=True)

# ----------------- INTRO -----------------
def intro():
    try:
        styled_text = pyfiglet.figlet_format('LOGSENTRY', font='slant')
        print(Fore.CYAN + styled_text)
    except:
        print(Fore.CYAN + "\n==== LOGSENTRY ====\n")
    print(Fore.MAGENTA + "\t> by Pratham Mejari | Securing Your Data, Securing Your Future...\n")

# ----------------- HELPER -----------------
def display_logs(title, pattern, content, color=Fore.WHITE):
    refine = re.findall(pattern, content, re.MULTILINE)
    count = len(refine)

    print(Fore.CYAN + f"[*] {title}")
    print(Fore.GREEN + f"\t* Number of logs: {count}")
    print("-" * (len(refine[0]) + 10 if count > 0 else 20))

    if count > 0:
        for log in refine:
            print(color + log)
    else:
        print(Fore.RED + "No logs found.")
    print()
    return refine

# ----------------- SAVE LOGS -----------------
def save_logs(filtered_logs):
    filename = input(Fore.YELLOW + "[+] Enter filename to save logs: ")
    with open(filename, "w") as f:
        f.write("\n".join(filtered_logs))
    print(Fore.GREEN + f"Logs saved successfully to {filename}\n")

# ----------------- CUSTOM REGEX SEARCH -----------------
def custom_search(content):
    regex = input(Fore.YELLOW + "[+] Enter your regex pattern: ")
    matches = re.findall(regex, content, re.MULTILINE)
    if matches:
        print(Fore.CYAN + f"[*] Found {len(matches)} matches:")
        for match in matches:
            print(Fore.MAGENTA + match)
        save_option = input(Fore.YELLOW + "[+] Save these logs? (y/n): ")
        if save_option.lower() == 'y':
            save_logs(matches)
    else:
        print(Fore.RED + "No matches found.\n")

# ----------------- LINUX FUNCTIONS -----------------
def auth_failure(content):
    pattern = r"(authentication\s+failure.+|Kerberos\s+authentication\s+failed|Authentication\s+failed\s+from.+|Couldn't\sauthenticate.+)"
    logs = display_logs("AUTHENTICATION FAILURE LOGS :-", pattern, content, Fore.RED)
    return logs

def session_alerts(content):
    pattern = r"(session\s+opened.+|session\s+closed.+|ALERT.+)"
    logs = display_logs("SESSION OPENED/CLOSED/LOGROTATE ALERT :-", pattern, content, Fore.YELLOW)
    return logs

def connection(content):
    pattern = r"(connection\s+from.+|timed\s+out.+)"
    logs = display_logs("CONNECTION FROM USERS :-", pattern, content, Fore.BLUE)
    return logs

def start_stop_restart(content):
    pattern = r"(shutdown.+|startup.+|syslogd.+|Starting.+|started)"
    logs = display_logs("START/SHUTDOWN/RESTART :-", pattern, content, Fore.GREEN)
    return logs

def auto_detect(content):
    pattern = r"(Auto-detected.+|\*+\s+info\s+\[.+)"
    logs = display_logs("AUTO-DETECTION LOGS :-", pattern, content, Fore.CYAN)
    return logs

def login(content):
    pattern = r"(LOGIN\s+ON.+)"
    logs = display_logs("LOGIN USERS :-", pattern, content, Fore.MAGENTA)
    return logs

def operations(content):
    pattern = r"(removing\s+device.+|creating\s+device.+)"
    logs = display_logs("CREATING/REMOVING DEVICE NODES :-", pattern, content, Fore.YELLOW)
    return logs

def warnings(content):
    pattern = r"(notify\s+question.+|endpoint.+|warning:.+)"
    logs = display_logs("NOTIFY QUESTION/ENDPOINTS/WARNINGS :-", pattern, content, Fore.RED)
    return logs

def system_logs(content):
    pattern = r"(kernel:.+|random:.+|network:.+)"
    logs = display_logs("KERNEL/RANDOM/NETWORK LOGS :-", pattern, content, Fore.CYAN)
    return logs

# ----------------- WINDOWS FUNCTIONS -----------------
def load(content):
    pattern = r"(Loaded.+)"
    logs = display_logs("LOADED SERVICE LOGS :-", pattern, content, Fore.GREEN)
    return logs

def init_logs(content):
    pattern = r"(Scavenge:.+|Ending.+|Starting.+|service\s+starts\s+successfully.+|Startup.+|No\s+startup\s+processing\s+required.+)"
    logs = display_logs("INITIALIZE LOGS :-", pattern, content, Fore.CYAN)
    return logs

def sqm(content):
    pattern = r"(SQM:.+)"
    logs = display_logs("SOFTWARE QUALITY METRICS(SQM) LOGS :-", pattern, content, Fore.MAGENTA)
    return logs

def session_windows(content):
    pattern = r"(Session:.+|Failed\s+to\s+internally\s+open\s+package.+|Read\s+out\s+cached\s+package.+)"
    logs = display_logs("SESSION LOGS :-", pattern, content, Fore.BLUE)
    return logs

def warning_window(content):
    pattern = r"(Warning:.+|Expecting\s+attribute\s+name.+|Failed\s+to\s+get\s+next\s+element.+)"
    logs = display_logs("WARNING/EXPECTING/FAILED LOGS :-", pattern, content, Fore.RED)
    return logs

def loading(content):
    pattern = r"(Loading\s+offline\s+registry.+|Unloading\s+offline\s+registry.+|Offline\s+image\s+is:.+|manifest\s+caching.+)"
    logs = display_logs("LOADING/UNLOADING OFFLINE REGISTRY LOGS :-", pattern, content, Fore.YELLOW)
    return logs

# ----------------- ADDITIONAL ANALYSIS -----------------
def failed_login_attempts(content):
    pattern = r"(Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+))"
    matches = re.findall(pattern, content)
    if matches:
        print(Fore.RED + "[*] FAILED LOGIN ATTEMPTS")
        for full, user, ip in matches:
            print(f"User: {user}, IP: {ip}, Attempt: {full}")
        save_option = input(Fore.YELLOW + "[+] Save these logs? (y/n): ")
        if save_option.lower() == "y":
            save_logs([f"{full} | {user} | {ip}" for full, user, ip in matches])
    else:
        print(Fore.GREEN + "No failed login attempts found.\n")

def top_ips(content, top_n=5):
    pattern = r"from (\d+\.\d+\.\d+\.\d+)"
    ips = re.findall(pattern, content)
    if ips:
        counter = Counter(ips)
        print(Fore.CYAN + f"[*] TOP {top_n} IP ADDRESSES")
        for ip, count in counter.most_common(top_n):
            print(Fore.YELLOW + f"{ip} -> {count} times")
    else:
        print(Fore.GREEN + "No IP addresses found in logs.\n")

def severity_summary(content):
    levels = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
    for line in content.splitlines():
        for level in levels:
            if level in line.upper():
                levels[level] += 1
    print(Fore.CYAN + "[*] LOG SEVERITY SUMMARY")
    for level, count in levels.items():
        print(Fore.YELLOW + f"{level}: {count}")
    print()

# ----------------- MENUS -----------------
def linux_menu(content):
    while True:
        print(Fore.CYAN + "[*] LINUX OPTIONS :-")
        print("\t[1.] AUTHENTICATION FAILURE LOG.")
        print("\t[2.] SESSION OPENED/CLOSED/LOGROTATE ALERT LOG.")
        print("\t[3.] CONNECTION FROM USERS LOG.")
        print("\t[4.] START/SHUTDOWN/RESTART LOG.")
        print("\t[5.] AUTO-DETECTION LOG.")
        print("\t[6.] LOGIN USERS LOG.")
        print("\t[7.] CREATING/REMOVING DEVICE NODES LOG.")
        print("\t[8.] NOTIFY QUESTION/ENDPOINTS/WARNINGS LOG.")
        print("\t[9.] KERNEL/RANDOM/NETWORK LOG.")
        print("\t[10.] FAILED LOGIN ATTEMPTS")
        print("\t[11.] TOP IP ADDRESSES")
        print("\t[12.] LOG SEVERITY SUMMARY")
        print("\t[13.] CUSTOM REGEX SEARCH")
        print("\t[14.] ALL OF THE ABOVE")
        print("\t[15.] BACK TO MAIN MENU")
        print("\t[16.] EXIT\n")

        choice = input(Fore.YELLOW + "[+] Enter your choice: ")

        if choice == "1": auth_failure(content)
        elif choice == "2": session_alerts(content)
        elif choice == "3": connection(content)
        elif choice == "4": start_stop_restart(content)
        elif choice == "5": auto_detect(content)
        elif choice == "6": login(content)
        elif choice == "7": operations(content)
        elif choice == "8": warnings(content)
        elif choice == "9": system_logs(content)
        elif choice == "10": failed_login_attempts(content)
        elif choice == "11": top_ips(content)
        elif choice == "12": severity_summary(content)
        elif choice == "13": custom_search(content)
        elif choice == "14":
            auth_failure(content); session_alerts(content); connection(content)
            start_stop_restart(content); auto_detect(content); login(content)
            operations(content); warnings(content); system_logs(content)
            failed_login_attempts(content); top_ips(content); severity_summary(content)
        elif choice == "15": return
        elif choice == "16":
            print(Fore.GREEN + "\nThank you for choosing LOGSENTRY. Your trust is our priority!\n")
            sys.exit(0)

def windows_menu(content):
    while True:
        print(Fore.CYAN + "[*] WINDOWS OPTIONS :-")
        print("\t[1.] LOADED SERVICE LOG.")
        print("\t[2.] INITIALIZE LOG.")
        print("\t[3.] SOFTWARE QUALITY METRICS(SQM) LOG.")
        print("\t[4.] SESSION LOG.")
        print("\t[5.] WARNING/EXPECTING/FAILED LOG.")
        print("\t[6.] LOADING/UNLOADING OFFLINE REGISTRY LOG.")
        print("\t[7.] CUSTOM REGEX SEARCH")
        print("\t[8.] ALL OF THE ABOVE")
        print("\t[9.] BACK TO MAIN MENU")
        print("\t[10.] EXIT\n")

        choice = input(Fore.YELLOW + "[+] Enter your choice: ")

        if choice == "1": load(content)
        elif choice == "2": init_logs(content)
        elif choice == "3": sqm(content)
        elif choice == "4": session_windows(content)
        elif choice == "5": warning_window(content)
        elif choice == "6": loading(content)
        elif choice == "7": custom_search(content)
        elif choice == "8":
            load(content); init_logs(content); sqm(content)
            session_windows(content); warning_window(content); loading(content)
        elif choice == "9": return
        elif choice == "10":
            print(Fore.GREEN + "\nThank you for choosing LOGSENTRY. Your trust is our priority!\n")
            sys.exit(0)

# ----------------- MAIN MENU -----------------
def option():
    while True:
        print(Fore.CYAN + "[*] OPTIONS :-")
        print("\t[1.] Linux Log.")
        print("\t[2.] Windows Log.")
        print("\t[3.] Exit.\n")

        choice = input(Fore.YELLOW + "[+] Choose your Option: ")

        if choice == "1":
            filename = input(Fore.YELLOW + "[+] Enter Name of Linux Log File: ")
            try:
                with open(filename, "r") as f:
                    content = f.read()
                linux_menu(content)
            except FileNotFoundError:
                print(Fore.RED + "[!] File not found. Try again.\n")

        elif choice == "2":
            filename = input(Fore.YELLOW + "[+] Enter Name of Windows Log File: ")
            try:
                with open(filename, "r") as f:
                    content = f.read()
                windows_menu(content)
            except FileNotFoundError:
                print(Fore.RED + "[!] File not found. Try again.\n")

        elif choice == "3":
            print(Fore.GREEN + "\nThank you for choosing LOGSENTRY. Your trust is our priority!\n")
            sys.exit(0)

# ----------------- RUN -----------------
if __name__ == "__main__":
    intro()
    option()
