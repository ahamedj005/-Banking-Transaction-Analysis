"""

  BANK MANAGEMENT SYSTEM  (CSV Database, Single File, Console Application)

"""

import os
import csv
import sys
import json
import hashlib
import secrets
import getpass
import statistics
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ============================================================================
# PART 1 : FOLDER STRUCTURE, CONSTANTS, DATABASE (CSV) INITIALIZATION
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "bank_data")
BACKUP_DIR = os.path.join(BASE_DIR, "bank_backups")
REPORT_DIR = os.path.join(BASE_DIR, "bank_reports")
CHART_DIR = os.path.join(BASE_DIR, "bank_dashboard")

for d in (DATA_DIR, BACKUP_DIR, REPORT_DIR, CHART_DIR):
    os.makedirs(d, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.csv")
CUSTOMERS_FILE = os.path.join(DATA_DIR, "customers.csv")
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.csv")
TRANSACTIONS_FILE = os.path.join(DATA_DIR, "transactions.csv")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.csv")
ACTIVITY_FILE = os.path.join(DATA_DIR, "activity_log.csv")
FRAUD_FILE = os.path.join(DATA_DIR, "fraud_alerts.csv")
COUNTERS_FILE = os.path.join(DATA_DIR, "counters.json")

SCHEMAS = {
    USERS_FILE: ["username", "salt", "password_hash", "role", "linked_customer_id", "created_at"],
    CUSTOMERS_FILE: ["customer_id", "name", "dob", "gender", "phone", "email",
                      "address", "branch", "created_at", "updated_at", "status"],
    ACCOUNTS_FILE: ["account_number", "customer_id", "account_type", "branch",
                     "balance", "created_at", "status"],
    TRANSACTIONS_FILE: ["transaction_id", "timestamp", "account_number",
                         "related_account", "type", "channel", "amount",
                         "balance_after", "status", "remarks", "risk_score"],
    AUDIT_FILE: ["timestamp", "actor", "action", "entity", "entity_id", "details"],
    ACTIVITY_FILE: ["timestamp", "username", "role", "activity"],
    FRAUD_FILE: ["alert_id", "timestamp", "transaction_id", "account_number",
                 "risk_score", "reason"],
}

DEFAULT_COUNTERS = {"customer_id": 1000, "account_number": 100000000,
                     "transaction_id": 1, "alert_id": 1}


def init_database():
    """PART 1: Create CSV database files with headers if they do not exist."""
    for filepath, headers in SCHEMAS.items():
        if not os.path.exists(filepath):
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(headers)
    if not os.path.exists(COUNTERS_FILE):
        with open(COUNTERS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_COUNTERS, f, indent=2)


# ============================================================================
# UTILITY FUNCTIONS (CSV I/O, ID generation, hashing, validation, logging)
# ============================================================================

def read_csv(filepath):
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(filepath, rows, headers):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def append_csv(filepath, row, headers):
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=headers).writerow(row)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_counters():
    with open(COUNTERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_counters(counters):
    with open(COUNTERS_FILE, "w", encoding="utf-8") as f:
        json.dump(counters, f, indent=2)


def next_id(kind):
    """Auto-generate sequential IDs: customer_id, account_number, transaction_id, alert_id."""
    counters = load_counters()
    val = counters[kind]
    counters[kind] = val + 1
    save_counters(counters)
    if kind == "customer_id":
        return f"CUST{val}"
    if kind == "account_number":
        return str(val)
    if kind == "transaction_id":
        return f"TXN{val:08d}"
    if kind == "alert_id":
        return f"ALERT{val:05d}"
    return str(val)


def hash_password(password, salt=None):
    """SHA-256 password hashing with per-user random salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return salt, digest


def verify_password(password, salt, expected_hash):
    _, digest = hash_password(password, salt)
    return secrets.compare_digest(digest, expected_hash)


def log_audit(actor, action, entity, entity_id, details=""):
    append_csv(AUDIT_FILE, {
        "timestamp": now_str(), "actor": actor, "action": action,
        "entity": entity, "entity_id": entity_id, "details": details
    }, SCHEMAS[AUDIT_FILE])


def log_activity(username, role, activity):
    append_csv(ACTIVITY_FILE, {
        "timestamp": now_str(), "username": username, "role": role,
        "activity": activity
    }, SCHEMAS[ACTIVITY_FILE])


def valid_phone(phone):
    return phone.isdigit() and len(phone) == 10


def valid_amount(text):
    try:
        val = float(text)
        return val > 0
    except ValueError:
        return False


def pause():
    input("\nPress Enter to continue...")


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header(title):
    clear()
    print("=" * 70)
    print(title.center(70))
    print("=" * 70)


# ============================================================================
# PART 1 : LOGIN SYSTEM (ADMIN / USER)
# ============================================================================

class Session:
    def __init__(self):
        self.username = None
        self.role = None
        self.customer_id = None


def bootstrap_admin():
    """Create a default admin account on first run."""
    users = read_csv(USERS_FILE)
    if not any(u["role"] == "admin" for u in users):
        salt, pwd_hash = hash_password("admin123")
        append_csv(USERS_FILE, {
            "username": "admin", "salt": salt, "password_hash": pwd_hash,
            "role": "admin", "linked_customer_id": "", "created_at": now_str()
        }, SCHEMAS[USERS_FILE])
        log_audit("SYSTEM", "CREATE", "user", "admin", "Default admin bootstrapped")


def register_user_account(customer_id):
    """Register a login for a customer (role=user), used after Add Customer."""
    header("CREATE LOGIN FOR CUSTOMER")
    username = input("Choose username: ").strip()
    users = read_csv(USERS_FILE)
    if any(u["username"] == username for u in users):
        print("Username already exists.")
        return
    password = getpass.getpass("Choose password: ")
    salt, pwd_hash = hash_password(password)
    append_csv(USERS_FILE, {
        "username": username, "salt": salt, "password_hash": pwd_hash,
        "role": "user", "linked_customer_id": customer_id, "created_at": now_str()
    }, SCHEMAS[USERS_FILE])
    log_audit("SYSTEM", "CREATE", "user", username, f"Linked to {customer_id}")
    print("Login created successfully.")


def login():
    header("BANK MANAGEMENT SYSTEM - LOGIN")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    users = read_csv(USERS_FILE)
    for u in users:
        if u["username"] == username:
            if verify_password(password, u["salt"], u["password_hash"]):
                session = Session()
                session.username = username
                session.role = u["role"]
                session.customer_id = u["linked_customer_id"]
                log_activity(username, u["role"], "LOGIN SUCCESS")
                print(f"\nWelcome, {username} ({u['role'].upper()})")
                return session
            else:
                log_activity(username, u["role"], "LOGIN FAILED - bad password")
                print("Incorrect password.")
                return None
    log_activity(username, "unknown", "LOGIN FAILED - no such user")
    print("User not found.")
    return None


# ============================================================================
# PART 2 : CUSTOMER MANAGEMENT
# ============================================================================

def add_customer(session):
    header("ADD NEW CUSTOMER")
    name = input("Full Name: ").strip()
    dob = input("Date of Birth (YYYY-MM-DD): ").strip()
    gender = input("Gender (M/F/O): ").strip().upper()
    phone = input("Phone (10 digits): ").strip()
    if not valid_phone(phone):
        print("Invalid phone number. Aborting.")
        return
    email = input("Email: ").strip()
    address = input("Address: ").strip()
    branch = input("Branch: ").strip()

    customer_id = next_id("customer_id")
    row = {"customer_id": customer_id, "name": name, "dob": dob, "gender": gender,
           "phone": phone, "email": email, "address": address, "branch": branch,
           "created_at": now_str(), "updated_at": now_str(), "status": "ACTIVE"}
    append_csv(CUSTOMERS_FILE, row, SCHEMAS[CUSTOMERS_FILE])
    log_audit(session.username, "CREATE", "customer", customer_id, f"Added {name}")
    log_activity(session.username, session.role, f"Added customer {customer_id}")
    print(f"\nCustomer created successfully. Customer ID: {customer_id}")

    if input("Open a bank account for this customer now? (y/n): ").lower() == "y":
        open_account(session, customer_id)
    if input("Create a login for this customer? (y/n): ").lower() == "y":
        register_user_account(customer_id)


def find_customer(customer_id):
    for c in read_csv(CUSTOMERS_FILE):
        if c["customer_id"] == customer_id:
            return c
    return None


def update_customer(session):
    header("UPDATE CUSTOMER")
    cid = input("Enter Customer ID: ").strip()
    customers = read_csv(CUSTOMERS_FILE)
    for c in customers:
        if c["customer_id"] == cid:
            print(f"Leave blank to keep existing value.")
            for field in ("name", "phone", "email", "address", "branch"):
                new_val = input(f"{field.capitalize()} [{c[field]}]: ").strip()
                if new_val:
                    if field == "phone" and not valid_phone(new_val):
                        print("Invalid phone, skipping.")
                        continue
                    c[field] = new_val
            c["updated_at"] = now_str()
            write_csv(CUSTOMERS_FILE, customers, SCHEMAS[CUSTOMERS_FILE])
            log_audit(session.username, "UPDATE", "customer", cid, "Fields updated")
            log_activity(session.username, session.role, f"Updated customer {cid}")
            print("Customer updated.")
            return
    print("Customer not found.")


def delete_customer(session):
    header("DELETE (DEACTIVATE) CUSTOMER")
    cid = input("Enter Customer ID: ").strip()
    customers = read_csv(CUSTOMERS_FILE)
    accounts = read_csv(ACCOUNTS_FILE)
    active_accounts = [a for a in accounts if a["customer_id"] == cid and a["status"] == "ACTIVE"]
    if active_accounts:
        print("Cannot delete: customer has active accounts. Close accounts first.")
        return
    found = False
    for c in customers:
        if c["customer_id"] == cid:
            c["status"] = "DELETED"
            c["updated_at"] = now_str()
            found = True
    if found:
        write_csv(CUSTOMERS_FILE, customers, SCHEMAS[CUSTOMERS_FILE])
        log_audit(session.username, "DELETE", "customer", cid, "Marked DELETED")
        log_activity(session.username, session.role, f"Deleted customer {cid}")
        print("Customer deleted (soft-delete).")
    else:
        print("Customer not found.")


def search_customer(session):
    header("SEARCH CUSTOMER")
    print("Search by: 1) Customer ID  2) Name  3) Phone")
    choice = input("Choice: ").strip()
    customers = read_csv(CUSTOMERS_FILE)
    query = input("Enter search value: ").strip().lower()
    results = []
    for c in customers:
        if choice == "1" and query == c["customer_id"].lower():
            results.append(c)
        elif choice == "2" and query in c["name"].lower():
            results.append(c)
        elif choice == "3" and query == c["phone"]:
            results.append(c)
    if not results:
        print("No matching customers found.")
    else:
        print_table(results, ["customer_id", "name", "phone", "email", "branch", "status"])
    log_activity(session.username, session.role, "Searched customer")


def view_all_customers(session):
    header("ALL CUSTOMERS")
    customers = read_csv(CUSTOMERS_FILE)
    if not customers:
        print("No customers yet.")
    else:
        print_table(customers, ["customer_id", "name", "phone", "branch", "status"])
    log_activity(session.username, session.role, "Viewed all customers")


def print_table(rows, columns):
    widths = {col: max(len(col), max((len(str(r.get(col, ''))) for r in rows), default=0)) for col in columns}
    line = " | ".join(col.upper().ljust(widths[col]) for col in columns)
    print(line)
    print("-" * len(line))
    for r in rows:
        print(" | ".join(str(r.get(col, "")).ljust(widths[col]) for col in columns))


# ============================================================================
# PART 3 : ACCOUNT MANAGEMENT
# ============================================================================

def open_account(session, customer_id=None):
    header("OPEN NEW ACCOUNT")
    if not customer_id:
        customer_id = input("Customer ID: ").strip()
    customer = find_customer(customer_id)
    if not customer:
        print("Customer not found.")
        return
    acc_type = input("Account Type (SAVINGS/CURRENT): ").strip().upper() or "SAVINGS"
    opening_balance = input("Opening Balance (min 500): ").strip()
    if not valid_amount(opening_balance) or float(opening_balance) < 500:
        print("Minimum opening balance is 500.")
        return
    account_number = next_id("account_number")
    row = {"account_number": account_number, "customer_id": customer_id,
           "account_type": acc_type, "branch": customer["branch"],
           "balance": f"{float(opening_balance):.2f}", "created_at": now_str(),
           "status": "ACTIVE"}
    append_csv(ACCOUNTS_FILE, row, SCHEMAS[ACCOUNTS_FILE])
    log_audit(session.username, "CREATE", "account", account_number,
              f"Opened for {customer_id}")
    print(f"Account opened successfully. Account Number: {account_number}")


def find_account(account_number):
    for a in read_csv(ACCOUNTS_FILE):
        if a["account_number"] == account_number:
            return a
    return None


def update_account_balance(account_number, new_balance):
    accounts = read_csv(ACCOUNTS_FILE)
    for a in accounts:
        if a["account_number"] == account_number:
            a["balance"] = f"{new_balance:.2f}"
    write_csv(ACCOUNTS_FILE, accounts, SCHEMAS[ACCOUNTS_FILE])


def record_transaction(account_number, related_account, txn_type, channel,
                        amount, balance_after, status, remarks, risk_score=0):
    txn_id = next_id("transaction_id")
    row = {"transaction_id": txn_id, "timestamp": now_str(),
           "account_number": account_number, "related_account": related_account,
           "type": txn_type, "channel": channel, "amount": f"{amount:.2f}",
           "balance_after": f"{balance_after:.2f}", "status": status,
           "remarks": remarks, "risk_score": risk_score}
    append_csv(TRANSACTIONS_FILE, row, SCHEMAS[TRANSACTIONS_FILE])
    return txn_id


def deposit(session):
    header("DEPOSIT")
    acc_no = input("Account Number: ").strip()
    account = find_account(acc_no)
    if not account or account["status"] != "ACTIVE":
        print("Account not found or inactive.")
        return
    amt = input("Amount to deposit: ").strip()
    if not valid_amount(amt):
        print("Invalid amount.")
        return
    amount = float(amt)
    new_balance = float(account["balance"]) + amount
    update_account_balance(acc_no, new_balance)
    risk = fraud_score(acc_no, "DEPOSIT", amount)
    txn_id = record_transaction(acc_no, "", "DEPOSIT", "BRANCH", amount,
                                 new_balance, "SUCCESS", "Cash/Cheque deposit", risk)
    log_audit(session.username, "DEPOSIT", "account", acc_no, f"+{amount}")
    log_activity(session.username, session.role, f"Deposit {amount} to {acc_no}")
    print(f"Deposit successful. Txn ID: {txn_id}. New Balance: {new_balance:.2f}")


def withdraw(session, channel="BRANCH"):
    header(f"WITHDRAW ({channel})")
    acc_no = input("Account Number: ").strip()
    account = find_account(acc_no)
    if not account or account["status"] != "ACTIVE":
        print("Account not found or inactive.")
        return
    amt = input("Amount to withdraw: ").strip()
    if not valid_amount(amt):
        print("Invalid amount.")
        return
    amount = float(amt)
    balance = float(account["balance"])
    if channel == "ATM" and amount > 25000:
        print("ATM withdrawal limit is 25000 per transaction.")
        return
    if amount > balance:
        print("Insufficient balance.")
        record_transaction(acc_no, "", "WITHDRAW", channel, amount, balance,
                            "FAILED", "Insufficient funds")
        return
    new_balance = balance - amount
    update_account_balance(acc_no, new_balance)
    risk = fraud_score(acc_no, "WITHDRAW", amount)
    txn_id = record_transaction(acc_no, "", "WITHDRAW", channel, amount,
                                 new_balance, "SUCCESS", f"{channel} withdrawal", risk)
    log_audit(session.username, "WITHDRAW", "account", acc_no, f"-{amount}")
    log_activity(session.username, session.role, f"Withdraw {amount} from {acc_no}")
    print(f"Withdrawal successful. Txn ID: {txn_id}. New Balance: {new_balance:.2f}")
    if risk >= 70:
        print(f"⚠ FRAUD ALERT: This transaction was flagged with risk score {risk}.")


def fund_transfer(session, channel="NEFT"):
    header(f"FUND TRANSFER ({channel})")
    src = input("From Account Number: ").strip()
    dst = input("To Account Number: ").strip()
    src_acc = find_account(src)
    dst_acc = find_account(dst)
    if not src_acc or src_acc["status"] != "ACTIVE":
        print("Source account invalid.")
        return
    if not dst_acc or dst_acc["status"] != "ACTIVE":
        print("Destination account invalid.")
        return
    amt = input("Amount to transfer: ").strip()
    if not valid_amount(amt):
        print("Invalid amount.")
        return
    amount = float(amt)
    if channel == "IMPS" and amount > 200000:
        print("IMPS limit is 2,00,000.")
        return
    if channel == "RTGS" and amount < 200000:
        print("RTGS minimum amount is 2,00,000.")
        return
    if channel == "UPI" and amount > 100000:
        print("UPI limit is 1,00,000.")
        return
    src_balance = float(src_acc["balance"])
    if amount > src_balance:
        print("Insufficient balance.")
        record_transaction(src, dst, "TRANSFER", channel, amount, src_balance,
                            "FAILED", "Insufficient funds")
        return
    new_src_balance = src_balance - amount
    new_dst_balance = float(dst_acc["balance"]) + amount
    update_account_balance(src, new_src_balance)
    update_account_balance(dst, new_dst_balance)
    risk = fraud_score(src, "TRANSFER", amount)
    txn_id = record_transaction(src, dst, "TRANSFER_OUT", channel, amount,
                                 new_src_balance, "SUCCESS", f"To {dst}", risk)
    record_transaction(dst, src, "TRANSFER_IN", channel, amount,
                        new_dst_balance, "SUCCESS", f"From {src}", risk)
    log_audit(session.username, "TRANSFER", "account", src, f"{amount} -> {dst} via {channel}")
    log_activity(session.username, session.role, f"{channel} transfer {amount} {src}->{dst}")
    print(f"Transfer successful via {channel}. Txn ID: {txn_id}.")
    if risk >= 70:
        print(f"⚠ FRAUD ALERT: This transaction was flagged with risk score {risk}.")


def balance_enquiry(session):
    header("BALANCE ENQUIRY")
    acc_no = input("Account Number: ").strip()
    account = find_account(acc_no)
    if not account:
        print("Account not found.")
        return
    print(f"Account: {acc_no}  |  Type: {account['account_type']}  |  "
          f"Status: {account['status']}")
    print(f"Current Balance: {float(account['balance']):.2f}")
    log_activity(session.username, session.role, f"Balance enquiry {acc_no}")


def mini_statement(session):
    header("MINI STATEMENT (Last 10 Transactions)")
    acc_no = input("Account Number: ").strip()
    txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["account_number"] == acc_no]
    txns.sort(key=lambda t: t["timestamp"], reverse=True)
    last10 = txns[:10]
    if not last10:
        print("No transactions found.")
    else:
        print_table(last10, ["transaction_id", "timestamp", "type", "channel",
                              "amount", "balance_after", "status"])
    log_activity(session.username, session.role, f"Mini statement {acc_no}")


# ============================================================================
# PART 4 : TRANSACTION MANAGEMENT (channel wrappers) + HISTORY
# ============================================================================

def upi_transfer(session):
    fund_transfer(session, channel="UPI")


def neft_transfer(session):
    fund_transfer(session, channel="NEFT")


def imps_transfer(session):
    fund_transfer(session, channel="IMPS")


def rtgs_transfer(session):
    fund_transfer(session, channel="RTGS")


def atm_withdrawal(session):
    withdraw(session, channel="ATM")


def transaction_history(session):
    header("TRANSACTION HISTORY")
    acc_no = input("Account Number (blank = all): ").strip()
    txns = read_csv(TRANSACTIONS_FILE)
    if acc_no:
        txns = [t for t in txns if t["account_number"] == acc_no]
    txns.sort(key=lambda t: t["timestamp"], reverse=True)
    if not txns:
        print("No transactions found.")
    else:
        print_table(txns[:50], ["transaction_id", "timestamp", "account_number",
                                 "type", "channel", "amount", "status", "risk_score"])
    log_activity(session.username, session.role, f"Viewed transaction history {acc_no or 'ALL'}")


# ============================================================================
# PART 5 : FRAUD DETECTION (Risk Scoring + Suspicious Transaction Report)
# ============================================================================

def fraud_score(account_number, txn_type, amount):
    """
    Simple explainable risk model (0-100):
      +30  amount is a large spike vs account's historical average
      +25  more than 3 transactions on this account in the last 10 minutes (velocity)
      +20  transaction occurs late night (11 PM - 5 AM)
      +15  amount is suspiciously round (e.g. multiple of 10000) and > 50000
      +10  base risk for withdrawal/transfer > 100000
    """
    score = 0
    now = datetime.now()
    txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["account_number"] == account_number]

    amounts = [float(t["amount"]) for t in txns if t["status"] == "SUCCESS"]
    if len(amounts) >= 3:
        avg = statistics.mean(amounts)
        if avg > 0 and amount > 3 * avg:
            score += 30

    recent_cutoff = now - timedelta(minutes=10)
    recent_count = sum(1 for t in txns if _safe_parse(t["timestamp"]) and
                        _safe_parse(t["timestamp"]) >= recent_cutoff)
    if recent_count >= 3:
        score += 25

    if now.hour >= 23 or now.hour < 5:
        score += 20

    if amount % 10000 == 0 and amount > 50000:
        score += 15

    if txn_type in ("WITHDRAW", "TRANSFER") and amount > 100000:
        score += 10

    return min(score, 100)


def _safe_parse(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def raise_fraud_alert(txn):
    alert_id = next_id("alert_id")
    reason_parts = []
    risk = int(txn["risk_score"])
    if risk >= 70:
        reason_parts.append("High composite risk score")
    append_csv(FRAUD_FILE, {
        "alert_id": alert_id, "timestamp": now_str(),
        "transaction_id": txn["transaction_id"], "account_number": txn["account_number"],
        "risk_score": risk, "reason": "; ".join(reason_parts) or "Rule triggered"
    }, SCHEMAS[FRAUD_FILE])
    return alert_id


def suspicious_transaction_report(session):
    header("SUSPICIOUS TRANSACTION REPORT (Risk Score >= 60)")
    txns = read_csv(TRANSACTIONS_FILE)
    suspicious = [t for t in txns if t["risk_score"] and int(t["risk_score"]) >= 60]
    # backfill alerts for any not yet logged
    existing_alert_txns = {a["transaction_id"] for a in read_csv(FRAUD_FILE)}
    for t in suspicious:
        if t["transaction_id"] not in existing_alert_txns:
            raise_fraud_alert(t)
    if not suspicious:
        print("No suspicious transactions found.")
    else:
        print_table(suspicious, ["transaction_id", "timestamp", "account_number",
                                  "type", "channel", "amount", "risk_score"])
        print(f"\nTotal suspicious transactions: {len(suspicious)}")
    log_activity(session.username, session.role, "Viewed suspicious transaction report")


# ============================================================================
# PART 6 : REPORTS
# ============================================================================

def customer_activity_report(session):
    """Full activity for a single customer: profile, accounts, all transactions, audit trail."""
    header("CUSTOMER ACTIVITY REPORT")
    cid = input("Enter Customer ID: ").strip()
    customer = find_customer(cid)
    if not customer:
        print("Customer not found.")
        return

    accounts = [a for a in read_csv(ACCOUNTS_FILE) if a["customer_id"] == cid]
    acc_numbers = {a["account_number"] for a in accounts}
    txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["account_number"] in acc_numbers]
    txns.sort(key=lambda t: t["timestamp"], reverse=True)
    audits = [a for a in read_csv(AUDIT_FILE) if a["entity_id"] in acc_numbers or a["entity_id"] == cid]

    lines = []
    lines.append(f"CUSTOMER ACTIVITY REPORT - Generated {now_str()}")
    lines.append("=" * 70)
    lines.append(f"Customer ID : {customer['customer_id']}")
    lines.append(f"Name        : {customer['name']}")
    lines.append(f"Phone/Email : {customer['phone']} / {customer['email']}")
    lines.append(f"Branch      : {customer['branch']}")
    lines.append(f"Status      : {customer['status']}")
    lines.append("")
    lines.append(f"ACCOUNTS ({len(accounts)}):")
    for a in accounts:
        lines.append(f"  - {a['account_number']} | {a['account_type']} | "
                      f"Balance: {a['balance']} | {a['status']}")
    lines.append("")
    lines.append(f"TRANSACTIONS ({len(txns)}):")
    for t in txns:
        lines.append(f"  [{t['timestamp']}] {t['transaction_id']} {t['type']} "
                      f"via {t['channel']} amt={t['amount']} status={t['status']} "
                      f"risk={t['risk_score']}")
    lines.append("")
    lines.append(f"AUDIT TRAIL ({len(audits)}):")
    for a in audits:
        lines.append(f"  [{a['timestamp']}] {a['actor']} {a['action']} "
                      f"{a['entity']}:{a['entity_id']} - {a['details']}")

    report_text = "\n".join(lines)
    print(report_text)

    filename = os.path.join(REPORT_DIR, f"customer_activity_{cid}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\nReport saved to: {filename}")
    log_activity(session.username, session.role, f"Generated customer activity report {cid}")


def monthly_transaction_report(session):
    header("MONTHLY TRANSACTION REPORT")
    month = input("Enter month (YYYY-MM): ").strip()
    txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["timestamp"].startswith(month)]
    if not txns:
        print("No transactions for that month.")
        return
    total_amount = sum(float(t["amount"]) for t in txns)
    by_type = defaultdict(float)
    by_channel = defaultdict(int)
    for t in txns:
        by_type[t["type"]] += float(t["amount"])
        by_channel[t["channel"]] += 1
    print(f"Total Transactions : {len(txns)}")
    print(f"Total Amount Moved : {total_amount:.2f}")
    print("\nBy Type:")
    for k, v in by_type.items():
        print(f"  {k:15s} {v:.2f}")
    print("\nBy Channel (count):")
    for k, v in by_channel.items():
        print(f"  {k:15s} {v}")
    log_activity(session.username, session.role, f"Monthly report {month}")


def account_summary_report(session):
    header("ACCOUNT SUMMARY REPORT")
    accounts = read_csv(ACCOUNTS_FILE)
    if not accounts:
        print("No accounts.")
        return
    total_balance = sum(float(a["balance"]) for a in accounts)
    active = sum(1 for a in accounts if a["status"] == "ACTIVE")
    print(f"Total Accounts : {len(accounts)}  (Active: {active})")
    print(f"Total Balance Across Bank: {total_balance:.2f}")
    print_table(accounts, ["account_number", "customer_id", "account_type", "branch", "balance", "status"])
    log_activity(session.username, session.role, "Account summary report")


def branch_report(session):
    header("BRANCH REPORT")
    accounts = read_csv(ACCOUNTS_FILE)
    branch_stats = defaultdict(lambda: {"count": 0, "balance": 0.0})
    for a in accounts:
        branch_stats[a["branch"]]["count"] += 1
        branch_stats[a["branch"]]["balance"] += float(a["balance"])
    for branch, stats in branch_stats.items():
        print(f"{branch:20s} Accounts: {stats['count']:5d}   Total Balance: {stats['balance']:.2f}")
    log_activity(session.username, session.role, "Branch report")


# ============================================================================
# PART 7 : EXECUTIVE DASHBOARD (KPI Cards + 6 Matplotlib Charts)
# ============================================================================

def executive_dashboard(session):
    header("EXECUTIVE DASHBOARD")
    customers = read_csv(CUSTOMERS_FILE)
    accounts = read_csv(ACCOUNTS_FILE)
    txns = read_csv(TRANSACTIONS_FILE)
    alerts = read_csv(FRAUD_FILE)

    total_customers = len(customers)
    total_accounts = len(accounts)
    total_balance = sum(float(a["balance"]) for a in accounts)
    total_txns = len(txns)
    success_txns = sum(1 for t in txns if t["status"] == "SUCCESS")
    success_rate = (success_txns / total_txns * 100) if total_txns else 0
    fraud_alerts_count = len(alerts)

    print("KPI CARDS")
    print("-" * 50)
    print(f" Total Customers       : {total_customers}")
    print(f" Total Accounts        : {total_accounts}")
    print(f" Total Bank Balance    : {total_balance:,.2f}")
    print(f" Total Transactions    : {total_txns}")
    print(f" Transaction Success % : {success_rate:.1f}%")
    print(f" Fraud Alerts Raised   : {fraud_alerts_count}")
    print("-" * 50)

    if not MATPLOTLIB_AVAILABLE:
        print("\nmatplotlib not installed - charts skipped. Run: pip install matplotlib")
        log_activity(session.username, session.role, "Viewed dashboard (no charts)")
        return

    if not txns:
        print("\nNo transaction data yet - charts skipped.")
        log_activity(session.username, session.role, "Viewed dashboard (no data)")
        return

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle("Bank Executive Dashboard", fontsize=16, fontweight="bold")

    # Chart 1: Transactions by type (bar)
    type_counts = defaultdict(int)
    for t in txns:
        type_counts[t["type"]] += 1
    axes[0, 0].bar(type_counts.keys(), type_counts.values(), color="#2b6cb0")
    axes[0, 0].set_title("Transactions by Type")
    axes[0, 0].tick_params(axis="x", rotation=30)

    # Chart 2: Transactions by channel (pie)
    channel_counts = defaultdict(int)
    for t in txns:
        channel_counts[t["channel"]] += 1
    axes[0, 1].pie(channel_counts.values(), labels=channel_counts.keys(), autopct="%1.0f%%")
    axes[0, 1].set_title("Transaction Channel Share")

    # Chart 3: Account balance distribution by account type (bar)
    type_balance = defaultdict(float)
    for a in accounts:
        type_balance[a["account_type"]] += float(a["balance"])
    axes[0, 2].bar(type_balance.keys(), type_balance.values(), color="#38a169")
    axes[0, 2].set_title("Balance by Account Type")

    # Chart 4: Daily transaction volume (line)
    daily_totals = defaultdict(float)
    for t in txns:
        day = t["timestamp"][:10]
        daily_totals[day] += float(t["amount"])
    days_sorted = sorted(daily_totals.keys())
    axes[1, 0].plot(days_sorted, [daily_totals[d] for d in days_sorted],
                     marker="o", color="#d69e2e")
    axes[1, 0].set_title("Daily Transaction Volume")
    axes[1, 0].tick_params(axis="x", rotation=45)

    # Chart 5: Risk score distribution (histogram)
    risk_scores = [int(t["risk_score"]) for t in txns if t["risk_score"] not in ("", None)]
    axes[1, 1].hist(risk_scores if risk_scores else [0], bins=10, color="#e53e3e")
    axes[1, 1].set_title("Risk Score Distribution")

    # Chart 6: Accounts opened per branch (bar)
    branch_counts = defaultdict(int)
    for a in accounts:
        branch_counts[a["branch"]] += 1
    axes[1, 2].bar(branch_counts.keys(), branch_counts.values(), color="#805ad5")
    axes[1, 2].set_title("Accounts per Branch")
    axes[1, 2].tick_params(axis="x", rotation=30)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out_path = os.path.join(CHART_DIR, f"dashboard_{datetime.now().strftime('%Y%m%d%H%M%S')}.png")
    plt.savefig(out_path, dpi=150)
    print(f"\nDashboard charts saved to: {out_path}")
    try:
        plt.show()
    except Exception:
        pass
    log_activity(session.username, session.role, "Viewed executive dashboard")


# ============================================================================
# PART 8 : BACKUP & RESTORE, ACTIVITY LOG, AUDIT TRAIL VIEWER
# ============================================================================

def backup_database(session):
    header("BACKUP DATABASE")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_dir = os.path.join(BACKUP_DIR, f"backup_{ts}")
    os.makedirs(target_dir, exist_ok=True)
    for filepath in SCHEMAS.keys():
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as src:
                content = src.read()
            with open(os.path.join(target_dir, os.path.basename(filepath)), "w", encoding="utf-8") as dst:
                dst.write(content)
    if os.path.exists(COUNTERS_FILE):
        with open(COUNTERS_FILE, "r", encoding="utf-8") as src:
            content = src.read()
        with open(os.path.join(target_dir, "counters.json"), "w", encoding="utf-8") as dst:
            dst.write(content)
    log_audit(session.username, "BACKUP", "database", ts, target_dir)
    log_activity(session.username, session.role, f"Backup created at {target_dir}")
    print(f"Backup completed: {target_dir}")


def restore_database(session):
    header("RESTORE DATABASE")
    backups = sorted(os.listdir(BACKUP_DIR))
    if not backups:
        print("No backups available.")
        return
    for i, b in enumerate(backups, 1):
        print(f"{i}. {b}")
    choice = input("Select backup number to restore: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(backups)):
        print("Invalid choice.")
        return
    chosen = backups[int(choice) - 1]
    source_dir = os.path.join(BACKUP_DIR, chosen)
    confirm = input(f"This will overwrite current data with '{chosen}'. Confirm? (y/n): ")
    if confirm.lower() != "y":
        print("Restore cancelled.")
        return
    for filepath in SCHEMAS.keys():
        src_path = os.path.join(source_dir, os.path.basename(filepath))
        if os.path.exists(src_path):
            with open(src_path, "r", encoding="utf-8") as src:
                content = src.read()
            with open(filepath, "w", encoding="utf-8") as dst:
                dst.write(content)
    src_counters = os.path.join(source_dir, "counters.json")
    if os.path.exists(src_counters):
        with open(src_counters, "r", encoding="utf-8") as src:
            content = src.read()
        with open(COUNTERS_FILE, "w", encoding="utf-8") as dst:
            dst.write(content)
    log_audit(session.username, "RESTORE", "database", chosen, source_dir)
    log_activity(session.username, session.role, f"Restored backup {chosen}")
    print("Restore complete.")


def view_activity_log(session):
    header("ACTIVITY LOG (Last 30)")
    logs = read_csv(ACTIVITY_FILE)
    logs.sort(key=lambda l: l["timestamp"], reverse=True)
    print_table(logs[:30], ["timestamp", "username", "role", "activity"])


def view_audit_trail(session):
    header("AUDIT TRAIL (Last 30)")
    logs = read_csv(AUDIT_FILE)
    logs.sort(key=lambda l: l["timestamp"], reverse=True)
    print_table(logs[:30], ["timestamp", "actor", "action", "entity", "entity_id", "details"])


# ============================================================================
# MAIN MENUS
# ============================================================================

def customer_management_menu(session):
    actions = {
        "1": ("Add Customer", add_customer),
        "2": ("Update Customer", update_customer),
        "3": ("Delete Customer", delete_customer),
        "4": ("Search Customer", search_customer),
        "5": ("View All Customers", view_all_customers),
        "6": ("Open Account for Existing Customer", open_account),
        "0": ("Back", None),
    }
    while True:
        header("CUSTOMER MANAGEMENT")
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice in actions and actions[choice][1]:
            actions[choice][1](session)
            pause()


def account_management_menu(session):
    actions = {
        "1": ("Deposit", deposit),
        "2": ("Withdraw", withdraw),
        "3": ("Fund Transfer (generic/NEFT)", fund_transfer),
        "4": ("Balance Enquiry", balance_enquiry),
        "5": ("Mini Statement", mini_statement),
        "0": ("Back", None),
    }
    while True:
        header("ACCOUNT MANAGEMENT")
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice in actions and actions[choice][1]:
            actions[choice][1](session)
            pause()


def transaction_management_menu(session):
    actions = {
        "1": ("UPI Transfer", upi_transfer),
        "2": ("NEFT Transfer", neft_transfer),
        "3": ("IMPS Transfer", imps_transfer),
        "4": ("RTGS Transfer", rtgs_transfer),
        "5": ("ATM Withdrawal", atm_withdrawal),
        "6": ("Transaction History", transaction_history),
        "0": ("Back", None),
    }
    while True:
        header("TRANSACTION MANAGEMENT")
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice in actions and actions[choice][1]:
            actions[choice][1](session)
            pause()


def fraud_menu(session):
    while True:
        header("FRAUD DETECTION")
        print("1. Suspicious Transaction Report")
        print("0. Back")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice == "1":
            suspicious_transaction_report(session)
            pause()


def reports_menu(session):
    actions = {
        "1": ("Customer Activity Report", customer_activity_report),
        "2": ("Monthly Transaction Report", monthly_transaction_report),
        "3": ("Account Summary Report", account_summary_report),
        "4": ("Branch Report", branch_report),
        "0": ("Back", None),
    }
    while True:
        header("REPORTS")
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice in actions and actions[choice][1]:
            actions[choice][1](session)
            pause()


def system_menu(session):
    actions = {
        "1": ("Backup Database", backup_database),
        "2": ("Restore Database", restore_database),
        "3": ("View Activity Log", view_activity_log),
        "4": ("View Audit Trail", view_audit_trail),
        "0": ("Back", None),
    }
    while True:
        header("BACKUP, RESTORE & SYSTEM LOGS")
        for k, (label, _) in actions.items():
            print(f"{k}. {label}")
        choice = input("\nChoice: ").strip()
        if choice == "0":
            return
        if choice in actions and actions[choice][1]:
            actions[choice][1](session)
            pause()


def main_menu(session):
    while True:
        header(f"MAIN MENU  |  User: {session.username} ({session.role.upper()})")
        print("1. Customer Management")
        print("2. Account Management")
        print("3. Transaction Management")
        print("4. Fraud Detection")
        print("5. Reports")
        print("6. Executive Dashboard")
        print("7. Backup / Restore / Logs")
        print("8. Logout")
        print("0. Exit")
        choice = input("\nChoice: ").strip()

        if choice == "1":
            customer_management_menu(session)
        elif choice == "2":
            account_management_menu(session)
        elif choice == "3":
            transaction_management_menu(session)
        elif choice == "4":
            fraud_menu(session)
        elif choice == "5":
            reports_menu(session)
        elif choice == "6":
            executive_dashboard(session)
            pause()
        elif choice == "7":
            if session.role != "admin":
                print("Admin access required.")
                pause()
                continue
            system_menu(session)
        elif choice == "8":
            log_activity(session.username, session.role, "LOGOUT")
            print("Logged out.")
            return
        elif choice == "0":
            log_activity(session.username, session.role, "LOGOUT (exit)")
            print("Goodbye.")
            sys.exit(0)
        else:
            print("Invalid choice.")
            pause()


def run():
    init_database()
    bootstrap_admin()
    while True:
        session = login()
        if session:
            main_menu(session)
        else:
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != "y":
                break


if __name__ == "__main__":
    print("Default admin login -> username: admin | password: admin123")
    print("(Change this in production. Password is SHA-256 hashed with a random salt.)")
    run()
