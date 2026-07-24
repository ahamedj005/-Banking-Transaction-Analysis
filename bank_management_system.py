"""
BANK MANAGEMENT SYSTEM - STREAMLIT VERSION (CSV Database, Single File)
Run: streamlit run bank_app.py
Default admin login -> username: admin | password: admin123
"""

import os
import csv
import json
import random
import hashlib
import secrets
import statistics
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from collections import defaultdict

# ============================================================================
# CONSTANTS, PATHS, SCHEMAS
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "bank_data")
BACKUP_DIR = os.path.join(BASE_DIR, "bank_backups")

for d in (DATA_DIR, BACKUP_DIR):
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

# ----------------------------------------------------------------------------
# SEED DATA CONFIG
# ----------------------------------------------------------------------------
BRANCHES = ["Chennai", "Coimbatore", "Madurai", "Tiruppur", "Salem"]
CUSTOMERS_PER_BRANCH = 85
EMPLOYEES_PER_BRANCH = 10

FIRST_NAMES = [
    "Arun", "Bala", "Chitra", "Dinesh", "Elango", "Farida", "Gopal", "Hema",
    "Indira", "Jayaram", "Kavitha", "Lakshmi", "Mani", "Nandhini", "Oviya",
    "Prakash", "Rani", "Senthil", "Tamil", "Uma", "Vijay", "Yazhini",
    "Kumar", "Meena", "Suresh", "Priya", "Ravi", "Divya", "Karthik", "Anitha",
    "Selvam", "Revathi", "Murugan", "Sangeetha", "Vignesh", "Deepa", "Ramesh",
    "Saranya", "Vasanth", "Nithya", "Manoj", "Swathi", "Ganesh", "Preethi",
]
LAST_NAMES = [
    "Kumar", "Raj", "Subramaniam", "Pillai", "Nair", "Chettiar", "Iyer",
    "Gounder", "Mudaliar", "Reddy", "Rao", "Naidu", "Krishnan", "Perumal",
    "Shanmugam", "Velu", "Balan", "Doss", "Rajan", "Moorthy",
]

random.seed(42)  # deterministic seed data across runs


def init_database():
    for filepath, headers in SCHEMAS.items():
        if not os.path.exists(filepath):
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(headers)
    if not os.path.exists(COUNTERS_FILE):
        with open(COUNTERS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_COUNTERS, f, indent=2)


# ============================================================================
# CSV I/O, ID GENERATION, HASHING, LOGGING, VALIDATION
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


def valid_amount(val):
    try:
        return float(val) > 0
    except (ValueError, TypeError):
        return False


def bootstrap_admin():
    users = read_csv(USERS_FILE)
    if not any(u["role"] == "admin" for u in users):
        salt, pwd_hash = hash_password("admin123")
        append_csv(USERS_FILE, {
            "username": "admin", "salt": salt, "password_hash": pwd_hash,
            "role": "admin", "linked_customer_id": "", "created_at": now_str()
        }, SCHEMAS[USERS_FILE])
        log_audit("SYSTEM", "CREATE", "user", "admin", "Default admin bootstrapped")


# ----------------------------------------------------------------------------
# SAMPLE DATA SEEDING
# ----------------------------------------------------------------------------

def _random_phone():
    return "9" + "".join(str(random.randint(0, 9)) for _ in range(9))


def _random_dob():
    start = datetime(1955, 1, 1)
    end = datetime(2005, 12, 31)
    delta_days = (end - start).days
    return (start + timedelta(days=random.randint(0, delta_days))).strftime("%Y-%m-%d")


def _slugify(name):
    return name.lower().replace(" ", ".").replace("'", "")


def seed_sample_data():
    """Populate 85 customers + 10 employees per branch, each customer gets one
    seeded SAVINGS account. Idempotent: skips entirely if customers.csv already
    has data, so re-running the app never duplicates rows."""
    existing_customers = read_csv(CUSTOMERS_FILE)
    if existing_customers:
        return  # already seeded (or real data already exists) - do nothing

    new_customers = []
    new_accounts = []
    new_users = []
    used_emails = set()
    used_usernames = set()

    for branch in BRANCHES:
        branch_slug = branch.lower()

        # ---- customers ----
        for _ in range(CUSTOMERS_PER_BRANCH):
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            full_name = f"{first} {last}"
            customer_id = next_id("customer_id")

            email_base = f"{_slugify(full_name)}"
            email = f"{email_base}@example.com"
            suffix = 1
            while email in used_emails:
                suffix += 1
                email = f"{email_base}{suffix}@example.com"
            used_emails.add(email)

            gender = random.choice(["M", "F"])
            created = now_str()
            customer_row = {
                "customer_id": customer_id, "name": full_name, "dob": _random_dob(),
                "gender": gender, "phone": _random_phone(), "email": email,
                "address": f"{random.randint(1, 200)}, {branch} Main Road, Tamil Nadu",
                "branch": branch, "created_at": created, "updated_at": created,
                "status": "ACTIVE",
            }
            new_customers.append(customer_row)

            account_number = next_id("account_number")
            opening_balance = round(random.uniform(500, 150000), 2)
            account_row = {
                "account_number": account_number, "customer_id": customer_id,
                "account_type": random.choice(["SAVINGS", "SAVINGS", "SAVINGS", "CURRENT"]),
                "branch": branch, "balance": f"{opening_balance:.2f}",
                "created_at": created, "status": "ACTIVE",
            }
            new_accounts.append(account_row)

        # ---- employees (bank staff logins for this branch) ----
        for i in range(1, EMPLOYEES_PER_BRANCH + 1):
            username = f"{branch_slug}.emp{i}"
            counter = 1
            base_username = username
            while username in used_usernames:
                counter += 1
                username = f"{base_username}{counter}"
            used_usernames.add(username)

            salt, pwd_hash = hash_password("employee123")
            new_users.append({
                "username": username, "salt": salt, "password_hash": pwd_hash,
                "role": "employee", "linked_customer_id": "", "created_at": now_str(),
            })

    write_csv(CUSTOMERS_FILE, new_customers, SCHEMAS[CUSTOMERS_FILE])
    write_csv(ACCOUNTS_FILE, new_accounts, SCHEMAS[ACCOUNTS_FILE])

    # append employees onto whatever users already exist (keep admin row)
    existing_users = read_csv(USERS_FILE)
    write_csv(USERS_FILE, existing_users + new_users, SCHEMAS[USERS_FILE])

    log_audit("SYSTEM", "SEED", "database", "bulk",
              f"Seeded {len(new_customers)} customers, {len(new_accounts)} accounts, "
              f"{len(new_users)} employee logins across {len(BRANCHES)} branches")


def find_customer(customer_id):
    for c in read_csv(CUSTOMERS_FILE):
        if c["customer_id"] == customer_id:
            return c
    return None


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


def _safe_parse(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def fraud_score(account_number, txn_type, amount):
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


def raise_fraud_alert(txn):
    alert_id = next_id("alert_id")
    risk = int(txn["risk_score"])
    reason = "High composite risk score" if risk >= 70 else "Rule triggered"
    append_csv(FRAUD_FILE, {
        "alert_id": alert_id, "timestamp": now_str(),
        "transaction_id": txn["transaction_id"], "account_number": txn["account_number"],
        "risk_score": risk, "reason": reason
    }, SCHEMAS[FRAUD_FILE])
    return alert_id


def df(rows):
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ============================================================================
# STREAMLIT APP
# ============================================================================

st.set_page_config(page_title="Bank Management System", layout="wide")
init_database()
bootstrap_admin()
seed_sample_data()

if "session" not in st.session_state:
    st.session_state.session = None


def do_login(username, password):
    users = read_csv(USERS_FILE)
    for u in users:
        if u["username"] == username:
            if verify_password(password, u["salt"], u["password_hash"]):
                st.session_state.session = {
                    "username": username, "role": u["role"],
                    "customer_id": u["linked_customer_id"]
                }
                log_activity(username, u["role"], "LOGIN SUCCESS")
                return True
            log_activity(username, u["role"], "LOGIN FAILED - bad password")
            st.error("Incorrect password.")
            return False
    log_activity(username, "unknown", "LOGIN FAILED - no such user")
    st.error("User not found.")
    return False


# --------------------------- LOGIN SCREEN ---------------------------------
if st.session_state.session is None:
    st.title("🏦 Bank Management System - Login")
    st.info("Default admin login → username: **admin** | password: **admin123**")
    st.caption(
        "Sample data pre-loaded: 85 customers + 10 employee logins per branch "
        f"({', '.join(BRANCHES)}). Employee logins look like `chennai.emp1` / "
        "password `employee123`."
    )
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if do_login(username.strip(), password):
                st.rerun()
    st.stop()

session = st.session_state.session

# --------------------------- SIDEBAR NAV -----------------------------------
st.sidebar.title(f"👤 {session['username']} ({session['role'].upper()})")
menu_options = ["Customer Management", "Account Management", "Transaction Management",
                 "Fraud Detection", "Reports", "Executive Dashboard"]
if session["role"] == "admin":
    menu_options.append("Backup / Restore / Logs")
menu = st.sidebar.radio("Navigate", menu_options)

if st.sidebar.button("Logout"):
    log_activity(session["username"], session["role"], "LOGOUT")
    st.session_state.session = None
    st.rerun()

# ============================================================================
# CUSTOMER MANAGEMENT
# ============================================================================
if menu == "Customer Management":
    st.header("👥 Customer Management")
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["Add Customer", "Update Customer", "Delete Customer", "Search Customer", "View All"])

    with tab1:
        with st.form("add_customer_form"):
            name = st.text_input("Full Name")
            dob = st.date_input("Date of Birth")
            gender = st.selectbox("Gender", ["M", "F", "O"])
            phone = st.text_input("Phone (10 digits)")
            email = st.text_input("Email")
            address = st.text_area("Address")
            branch = st.selectbox("Branch", BRANCHES)
            submitted = st.form_submit_button("Add Customer")
            if submitted:
                if not valid_phone(phone):
                    st.error("Invalid phone number.")
                else:
                    customer_id = next_id("customer_id")
                    row = {"customer_id": customer_id, "name": name, "dob": str(dob),
                           "gender": gender, "phone": phone, "email": email,
                           "address": address, "branch": branch, "created_at": now_str(),
                           "updated_at": now_str(), "status": "ACTIVE"}
                    append_csv(CUSTOMERS_FILE, row, SCHEMAS[CUSTOMERS_FILE])
                    log_audit(session["username"], "CREATE", "customer", customer_id, f"Added {name}")
                    log_activity(session["username"], session["role"], f"Added customer {customer_id}")
                    st.success(f"Customer created! Customer ID: **{customer_id}**")

    with tab2:
        cid = st.text_input("Customer ID to update", key="upd_cid")
        if cid:
            customer = find_customer(cid)
            if not customer:
                st.error("Customer not found.")
            else:
                with st.form("update_customer_form"):
                    new_name = st.text_input("Name", value=customer["name"])
                    new_phone = st.text_input("Phone", value=customer["phone"])
                    new_email = st.text_input("Email", value=customer["email"])
                    new_address = st.text_area("Address", value=customer["address"])
                    new_branch = st.text_input("Branch", value=customer["branch"])
                    submitted = st.form_submit_button("Update")
                    if submitted:
                        if not valid_phone(new_phone):
                            st.error("Invalid phone number.")
                        else:
                            customers = read_csv(CUSTOMERS_FILE)
                            for c in customers:
                                if c["customer_id"] == cid:
                                    c.update(name=new_name, phone=new_phone, email=new_email,
                                             address=new_address, branch=new_branch,
                                             updated_at=now_str())
                            write_csv(CUSTOMERS_FILE, customers, SCHEMAS[CUSTOMERS_FILE])
                            log_audit(session["username"], "UPDATE", "customer", cid, "Fields updated")
                            log_activity(session["username"], session["role"], f"Updated customer {cid}")
                            st.success("Customer updated.")

    with tab3:
        cid_del = st.text_input("Customer ID to delete", key="del_cid")
        if st.button("Delete (Deactivate) Customer"):
            customers = read_csv(CUSTOMERS_FILE)
            accounts = read_csv(ACCOUNTS_FILE)
            active_accounts = [a for a in accounts if a["customer_id"] == cid_del and a["status"] == "ACTIVE"]
            if active_accounts:
                st.error("Cannot delete: customer has active accounts. Close accounts first.")
            else:
                found = False
                for c in customers:
                    if c["customer_id"] == cid_del:
                        c["status"] = "DELETED"
                        c["updated_at"] = now_str()
                        found = True
                if found:
                    write_csv(CUSTOMERS_FILE, customers, SCHEMAS[CUSTOMERS_FILE])
                    log_audit(session["username"], "DELETE", "customer", cid_del, "Marked DELETED")
                    log_activity(session["username"], session["role"], f"Deleted customer {cid_del}")
                    st.success("Customer deleted (soft-delete).")
                else:
                    st.error("Customer not found.")

    with tab4:
        search_type = st.selectbox("Search by", ["Customer ID", "Name", "Phone"])
        query = st.text_input("Search value").strip().lower()
        if query:
            customers = read_csv(CUSTOMERS_FILE)
            results = []
            for c in customers:
                if search_type == "Customer ID" and query == c["customer_id"].lower():
                    results.append(c)
                elif search_type == "Name" and query in c["name"].lower():
                    results.append(c)
                elif search_type == "Phone" and query == c["phone"]:
                    results.append(c)
            if results:
                st.dataframe(df(results), use_container_width=True)
            else:
                st.info("No matching customers found.")
            log_activity(session["username"], session["role"], "Searched customer")

    with tab5:
        customers = read_csv(CUSTOMERS_FILE)
        branch_filter = st.selectbox("Filter by branch", ["All"] + BRANCHES, key="view_all_branch")
        if branch_filter != "All":
            customers = [c for c in customers if c["branch"] == branch_filter]
        st.dataframe(df(customers), use_container_width=True)
        log_activity(session["username"], session["role"], "Viewed all customers")

# ============================================================================
# ACCOUNT MANAGEMENT
# ============================================================================
elif menu == "Account Management":
    st.header("🏦 Account Management")
    tab1, tab2, tab3, tab4 = st.tabs(
        ["Open Account", "Deposit / Withdraw", "Balance Enquiry", "Mini Statement"])

    with tab1:
        with st.form("open_account_form"):
            customer_id = st.text_input("Customer ID")
            acc_type = st.selectbox("Account Type", ["SAVINGS", "CURRENT"])
            opening_balance = st.number_input("Opening Balance (min 500)", min_value=0.0, step=100.0)
            submitted = st.form_submit_button("Open Account")
            if submitted:
                customer = find_customer(customer_id)
                if not customer:
                    st.error("Customer not found.")
                elif opening_balance < 500:
                    st.error("Minimum opening balance is 500.")
                else:
                    account_number = next_id("account_number")
                    row = {"account_number": account_number, "customer_id": customer_id,
                           "account_type": acc_type, "branch": customer["branch"],
                           "balance": f"{opening_balance:.2f}", "created_at": now_str(),
                           "status": "ACTIVE"}
                    append_csv(ACCOUNTS_FILE, row, SCHEMAS[ACCOUNTS_FILE])
                    log_audit(session["username"], "CREATE", "account", account_number, f"Opened for {customer_id}")
                    st.success(f"Account opened! Account Number: **{account_number}**")

    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Deposit")
            with st.form("deposit_form"):
                acc_no_d = st.text_input("Account Number", key="dep_acc")
                amt_d = st.number_input("Amount", min_value=0.0, step=100.0, key="dep_amt")
                if st.form_submit_button("Deposit"):
                    account = find_account(acc_no_d)
                    if not account or account["status"] != "ACTIVE":
                        st.error("Account not found or inactive.")
                    elif amt_d <= 0:
                        st.error("Invalid amount.")
                    else:
                        new_balance = float(account["balance"]) + amt_d
                        update_account_balance(acc_no_d, new_balance)
                        risk = fraud_score(acc_no_d, "DEPOSIT", amt_d)
                        txn_id = record_transaction(acc_no_d, "", "DEPOSIT", "BRANCH", amt_d,
                                                     new_balance, "SUCCESS", "Cash/Cheque deposit", risk)
                        log_audit(session["username"], "DEPOSIT", "account", acc_no_d, f"+{amt_d}")
                        st.success(f"Deposit successful. Txn ID: {txn_id}. New Balance: {new_balance:.2f}")

        with col2:
            st.subheader("Withdraw")
            with st.form("withdraw_form"):
                acc_no_w = st.text_input("Account Number", key="wd_acc")
                amt_w = st.number_input("Amount", min_value=0.0, step=100.0, key="wd_amt")
                channel_w = st.selectbox("Channel", ["BRANCH", "ATM"], key="wd_channel")
                if st.form_submit_button("Withdraw"):
                    account = find_account(acc_no_w)
                    if not account or account["status"] != "ACTIVE":
                        st.error("Account not found or inactive.")
                    elif amt_w <= 0:
                        st.error("Invalid amount.")
                    elif channel_w == "ATM" and amt_w > 25000:
                        st.error("ATM withdrawal limit is 25000 per transaction.")
                    else:
                        balance = float(account["balance"])
                        if amt_w > balance:
                            st.error("Insufficient balance.")
                            record_transaction(acc_no_w, "", "WITHDRAW", channel_w, amt_w, balance,
                                                "FAILED", "Insufficient funds")
                        else:
                            new_balance = balance - amt_w
                            update_account_balance(acc_no_w, new_balance)
                            risk = fraud_score(acc_no_w, "WITHDRAW", amt_w)
                            txn_id = record_transaction(acc_no_w, "", "WITHDRAW", channel_w, amt_w,
                                                         new_balance, "SUCCESS", f"{channel_w} withdrawal", risk)
                            log_audit(session["username"], "WITHDRAW", "account", acc_no_w, f"-{amt_w}")
                            st.success(f"Withdrawal successful. Txn ID: {txn_id}. New Balance: {new_balance:.2f}")
                            if risk >= 70:
                                st.warning(f"⚠ FRAUD ALERT: risk score {risk}")

    with tab3:
        acc_no_b = st.text_input("Account Number", key="bal_acc")
        if st.button("Check Balance"):
            account = find_account(acc_no_b)
            if not account:
                st.error("Account not found.")
            else:
                st.info(f"Type: {account['account_type']} | Status: {account['status']}")
                st.metric("Current Balance", f"{float(account['balance']):.2f}")
                log_activity(session["username"], session["role"], f"Balance enquiry {acc_no_b}")

    with tab4:
        acc_no_m = st.text_input("Account Number", key="mini_acc")
        if st.button("Show Mini Statement"):
            txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["account_number"] == acc_no_m]
            txns.sort(key=lambda t: t["timestamp"], reverse=True)
            st.dataframe(df(txns[:10]), use_container_width=True)
            log_activity(session["username"], session["role"], f"Mini statement {acc_no_m}")

# ============================================================================
# TRANSACTION MANAGEMENT
# ============================================================================
elif menu == "Transaction Management":
    st.header("💸 Transaction Management")
    channel = st.selectbox("Transfer Channel", ["UPI", "NEFT", "IMPS", "RTGS"])
    with st.form("transfer_form"):
        src = st.text_input("From Account Number")
        dst = st.text_input("To Account Number")
        amount = st.number_input("Amount", min_value=0.0, step=100.0)
        submitted = st.form_submit_button(f"Transfer via {channel}")
        if submitted:
            src_acc = find_account(src)
            dst_acc = find_account(dst)
            if not src_acc or src_acc["status"] != "ACTIVE":
                st.error("Source account invalid.")
            elif not dst_acc or dst_acc["status"] != "ACTIVE":
                st.error("Destination account invalid.")
            elif channel == "IMPS" and amount > 200000:
                st.error("IMPS limit is 2,00,000.")
            elif channel == "RTGS" and amount < 200000:
                st.error("RTGS minimum amount is 2,00,000.")
            elif channel == "UPI" and amount > 100000:
                st.error("UPI limit is 1,00,000.")
            else:
                src_balance = float(src_acc["balance"])
                if amount > src_balance:
                    st.error("Insufficient balance.")
                    record_transaction(src, dst, "TRANSFER", channel, amount, src_balance,
                                        "FAILED", "Insufficient funds")
                else:
                    new_src_balance = src_balance - amount
                    new_dst_balance = float(dst_acc["balance"]) + amount
                    update_account_balance(src, new_src_balance)
                    update_account_balance(dst, new_dst_balance)
                    risk = fraud_score(src, "TRANSFER", amount)
                    txn_id = record_transaction(src, dst, "TRANSFER_OUT", channel, amount,
                                                 new_src_balance, "SUCCESS", f"To {dst}", risk)
                    record_transaction(dst, src, "TRANSFER_IN", channel, amount,
                                        new_dst_balance, "SUCCESS", f"From {src}", risk)
                    log_audit(session["username"], "TRANSFER", "account", src, f"{amount} -> {dst} via {channel}")
                    st.success(f"Transfer successful via {channel}. Txn ID: {txn_id}.")
                    if risk >= 70:
                        st.warning(f"⚠ FRAUD ALERT: risk score {risk}")

    st.subheader("ATM Withdrawal")
    with st.form("atm_form"):
        atm_acc = st.text_input("Account Number", key="atm_acc")
        atm_amt = st.number_input("Amount", min_value=0.0, step=100.0, key="atm_amt")
        if st.form_submit_button("Withdraw at ATM"):
            account = find_account(atm_acc)
            if not account or account["status"] != "ACTIVE":
                st.error("Account not found or inactive.")
            elif atm_amt > 25000:
                st.error("ATM withdrawal limit is 25000 per transaction.")
            else:
                balance = float(account["balance"])
                if atm_amt > balance:
                    st.error("Insufficient balance.")
                else:
                    new_balance = balance - atm_amt
                    update_account_balance(atm_acc, new_balance)
                    risk = fraud_score(atm_acc, "WITHDRAW", atm_amt)
                    txn_id = record_transaction(atm_acc, "", "WITHDRAW", "ATM", atm_amt,
                                                 new_balance, "SUCCESS", "ATM withdrawal", risk)
                    st.success(f"ATM withdrawal successful. Txn ID: {txn_id}. New Balance: {new_balance:.2f}")

    st.subheader("Transaction History")
    hist_acc = st.text_input("Account Number (blank = all)", key="hist_acc")
    if st.button("View History"):
        txns = read_csv(TRANSACTIONS_FILE)
        if hist_acc:
            txns = [t for t in txns if t["account_number"] == hist_acc]
        txns.sort(key=lambda t: t["timestamp"], reverse=True)
        st.dataframe(df(txns[:50]), use_container_width=True)
        log_activity(session["username"], session["role"], f"Viewed transaction history {hist_acc or 'ALL'}")

# ============================================================================
# FRAUD DETECTION
# ============================================================================
elif menu == "Fraud Detection":
    st.header("🚨 Fraud Detection")
    txns = read_csv(TRANSACTIONS_FILE)
    suspicious = [t for t in txns if t["risk_score"] and int(t["risk_score"]) >= 60]
    existing_alert_txns = {a["transaction_id"] for a in read_csv(FRAUD_FILE)}
    for t in suspicious:
        if t["transaction_id"] not in existing_alert_txns:
            raise_fraud_alert(t)
    if suspicious:
        st.dataframe(df(suspicious), use_container_width=True)
        st.info(f"Total suspicious transactions: {len(suspicious)}")
    else:
        st.info("No suspicious transactions found.")
    log_activity(session["username"], session["role"], "Viewed suspicious transaction report")

# ============================================================================
# REPORTS
# ============================================================================
elif menu == "Reports":
    st.header("📊 Reports")
    report_type = st.selectbox("Report Type", ["Customer Activity", "Monthly Transaction",
                                                 "Account Summary", "Branch Report"])

    if report_type == "Customer Activity":
        cid = st.text_input("Customer ID")
        if st.button("Generate Report") and cid:
            customer = find_customer(cid)
            if not customer:
                st.error("Customer not found.")
            else:
                accounts = [a for a in read_csv(ACCOUNTS_FILE) if a["customer_id"] == cid]
                acc_numbers = {a["account_number"] for a in accounts}
                txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["account_number"] in acc_numbers]
                txns.sort(key=lambda t: t["timestamp"], reverse=True)
                st.subheader(f"{customer['name']} ({cid})")
                st.write(f"Phone/Email: {customer['phone']} / {customer['email']} | Branch: {customer['branch']}")
                st.write("**Accounts:**")
                st.dataframe(df(accounts), use_container_width=True)
                st.write("**Transactions:**")
                st.dataframe(df(txns), use_container_width=True)
                log_activity(session["username"], session["role"], f"Generated customer activity report {cid}")

    elif report_type == "Monthly Transaction":
        month = st.text_input("Enter month (YYYY-MM)")
        if st.button("Generate Report") and month:
            txns = [t for t in read_csv(TRANSACTIONS_FILE) if t["timestamp"].startswith(month)]
            if not txns:
                st.info("No transactions for that month.")
            else:
                total_amount = sum(float(t["amount"]) for t in txns)
                by_type = defaultdict(float)
                by_channel = defaultdict(int)
                for t in txns:
                    by_type[t["type"]] += float(t["amount"])
                    by_channel[t["channel"]] += 1
                col1, col2 = st.columns(2)
                col1.metric("Total Transactions", len(txns))
                col2.metric("Total Amount Moved", f"{total_amount:.2f}")
                st.write("**By Type:**")
                st.bar_chart(pd.Series(by_type))
                st.write("**By Channel (count):**")
                st.bar_chart(pd.Series(by_channel))
                log_activity(session["username"], session["role"], f"Monthly report {month}")

    elif report_type == "Account Summary":
        accounts = read_csv(ACCOUNTS_FILE)
        if not accounts:
            st.info("No accounts.")
        else:
            total_balance = sum(float(a["balance"]) for a in accounts)
            active = sum(1 for a in accounts if a["status"] == "ACTIVE")
            col1, col2 = st.columns(2)
            col1.metric("Total Accounts", len(accounts), f"Active: {active}")
            col2.metric("Total Balance", f"{total_balance:,.2f}")
            st.dataframe(df(accounts), use_container_width=True)
            log_activity(session["username"], session["role"], "Account summary report")

    elif report_type == "Branch Report":
        accounts = read_csv(ACCOUNTS_FILE)
        branch_stats = defaultdict(lambda: {"count": 0, "balance": 0.0})
        for a in accounts:
            branch_stats[a["branch"]]["count"] += 1
            branch_stats[a["branch"]]["balance"] += float(a["balance"])
        st.dataframe(pd.DataFrame(branch_stats).T, use_container_width=True)
        log_activity(session["username"], session["role"], "Branch report")

# ============================================================================
# EXECUTIVE DASHBOARD
# ============================================================================
elif menu == "Executive Dashboard":
    st.header("📈 Executive Dashboard")
    customers = read_csv(CUSTOMERS_FILE)
    accounts = read_csv(ACCOUNTS_FILE)
    txns = read_csv(TRANSACTIONS_FILE)
    alerts = read_csv(FRAUD_FILE)

    total_balance = sum(float(a["balance"]) for a in accounts)
    total_txns = len(txns)
    success_txns = sum(1 for t in txns if t["status"] == "SUCCESS")
    success_rate = (success_txns / total_txns * 100) if total_txns else 0

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Customers", len(customers))
    c2.metric("Accounts", len(accounts))
    c3.metric("Total Balance", f"{total_balance:,.0f}")
    c4.metric("Transactions", total_txns)
    c5.metric("Success %", f"{success_rate:.1f}%")
    c6.metric("Fraud Alerts", len(alerts))

    if not txns:
        st.info("No transaction data yet - charts skipped.")
    else:
        fig, axes = plt.subplots(2, 3, figsize=(18, 10))
        fig.suptitle("Bank Executive Dashboard", fontsize=16, fontweight="bold")

        type_counts = defaultdict(int)
        for t in txns:
            type_counts[t["type"]] += 1
        axes[0, 0].bar(type_counts.keys(), type_counts.values(), color="#2b6cb0")
        axes[0, 0].set_title("Transactions by Type")
        axes[0, 0].tick_params(axis="x", rotation=30)

        channel_counts = defaultdict(int)
        for t in txns:
            channel_counts[t["channel"]] += 1
        axes[0, 1].pie(channel_counts.values(), labels=channel_counts.keys(), autopct="%1.0f%%")
        axes[0, 1].set_title("Transaction Channel Share")

        type_balance = defaultdict(float)
        for a in accounts:
            type_balance[a["account_type"]] += float(a["balance"])
        axes[0, 2].bar(type_balance.keys(), type_balance.values(), color="#38a169")
        axes[0, 2].set_title("Balance by Account Type")

        daily_totals = defaultdict(float)
        for t in txns:
            daily_totals[t["timestamp"][:10]] += float(t["amount"])
        days_sorted = sorted(daily_totals.keys())
        axes[1, 0].plot(days_sorted, [daily_totals[d] for d in days_sorted], marker="o", color="#d69e2e")
        axes[1, 0].set_title("Daily Transaction Volume")
        axes[1, 0].tick_params(axis="x", rotation=45)

        risk_scores = [int(t["risk_score"]) for t in txns if t["risk_score"] not in ("", None)]
        axes[1, 1].hist(risk_scores if risk_scores else [0], bins=10, color="#e53e3e")
        axes[1, 1].set_title("Risk Score Distribution")

        branch_counts = defaultdict(int)
        for a in accounts:
            branch_counts[a["branch"]] += 1
        axes[1, 2].bar(branch_counts.keys(), branch_counts.values(), color="#805ad5")
        axes[1, 2].set_title("Accounts per Branch")
        axes[1, 2].tick_params(axis="x", rotation=30)

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        st.pyplot(fig)

    log_activity(session["username"], session["role"], "Viewed executive dashboard")

# ============================================================================
# BACKUP / RESTORE / LOGS (admin only)
# ============================================================================
elif menu == "Backup / Restore / Logs":
    st.header("🛠 Backup, Restore & System Logs")
    tab1, tab2, tab3, tab4 = st.tabs(["Backup", "Restore", "Activity Log", "Audit Trail"])

    with tab1:
        if st.button("Create Backup"):
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
            log_audit(session["username"], "BACKUP", "database", ts, target_dir)
            st.success(f"Backup completed: {target_dir}")

    with tab2:
        backups = sorted(os.listdir(BACKUP_DIR))
        if not backups:
            st.info("No backups available.")
        else:
            chosen = st.selectbox("Select backup to restore", backups)
            if st.button("Restore Selected Backup"):
                source_dir = os.path.join(BACKUP_DIR, chosen)
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
                log_audit(session["username"], "RESTORE", "database", chosen, source_dir)
                st.success("Restore complete.")

    with tab3:
        logs = read_csv(ACTIVITY_FILE)
        logs.sort(key=lambda l: l["timestamp"], reverse=True)
        st.dataframe(df(logs[:30]), use_container_width=True)

    with tab4:
        logs = read_csv(AUDIT_FILE)
        logs.sort(key=lambda l: l["timestamp"], reverse=True)
        st.dataframe(df(logs[:30]), use_container_width=True)
