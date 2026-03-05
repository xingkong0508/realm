import smtplib
import os
from email.mime.text import MIMEText
from datetime import datetime

# --- 配置区 ---
SMTP_SERVER = "smtp.gmail.com"  # 以 Gmail 为例
SMTP_PORT = 587
SENDER_EMAIL = "xxxxx"
# 注意：你需要去 Gmail 设置里申请“应用专用密码 (App Password)”，而不是普通登录密码
SENDER_PASSWORD = "xxxxx" 
RECEIVER_EMAIL = "xxxxx"

LOG_FILE = "/home/chenweilong0508/realm/realm_forensics.csv"
STATE_FILE = "/home/chenweilong0508/realm/last_line_pointer.txt"

def send_mail(content):
    msg = MIMEText(content)
    msg['Subject'] = f"Realm 战报 - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"邮件发送失败: {e}")
        return False

def main():
    # 1. 读取上一次发送到的行号
    last_line = 0
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            last_line = int(f.read().strip())

    # 2. 读取日志文件
    if not os.path.exists(LOG_FILE):
        return

    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()

    # 3. 提取新增部分
    total_lines = len(lines)
    if total_lines <= last_line:
        print("没有新日志，跳过。")
        return

    new_content = "".join(lines[last_line:])
    
    # 4. 发送并更新指针
    if send_mail(new_content):
        with open(STATE_FILE, 'w') as f:
            f.write(str(total_lines))
        print(f"成功发送 {total_lines - last_line} 行新增日志。")

if __name__ == "__main__":
    main()
