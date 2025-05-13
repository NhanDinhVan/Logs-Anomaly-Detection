import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_alert_email(
    sender_email: str,
    sender_password: str,
    recipient_email: str,
    log_info: dict,
    recon_error: float,
    smtp_server: str = "smtp.gmail.com",
    smtp_port: int = 587
) -> bool:
    """
    Gửi email thông báo khi phát hiện bất thường trong log Apache.
    
    Args:
        sender_email (str): Địa chỉ email người gửi.
        sender_password (str): Mật khẩu hoặc Mật khẩu ứng dụng của người gửi.
        recipient_email (str): Địa chỉ email người nhận.
        log_info (dict): Thông tin log từ parse_log_line (ip, path, datetime, v.v.).
        recon_error (float): Lỗi tái tạo từ autoencoder.
        smtp_server (str): Địa chỉ SMTP server (mặc định là Gmail).
        smtp_port (int): Cổng SMTP (mặc định là 587 cho TLS).
    
    Returns:
        bool: True nếu gửi thành công, False nếu thất bại.
    """
    try:
        # Tạo đối tượng MIMEMultipart
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"[ALERT] Phát hiện bất thường trong log Apache - {log_info['ip']}"

        # Tạo nội dung email
        body = f"""
        Phát hiện bất thường trong log Apache!
        
        Chi tiết:
        - IP: {log_info['ip']}
        - Đường dẫn: {log_info['path']}
        - Thời gian: {log_info['datetime']}
        - Phương thức: {log_info['method']}
        - Mã trạng thái: {log_info['status']}
        - Kích thước phản hồi: {log_info['size']}
        - Referrer: {log_info['referrer']}
        - User-Agent: {log_info['user_agent']}
        - Lỗi tái tạo (Reconstruction Error): {recon_error:.5f}
        
        Vui lòng kiểm tra hệ thống ngay lập tức!
        """
        msg.attach(MIMEText(body, 'plain'))

        # Kết nối tới SMTP server
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Bật TLS
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        print(f"Đã gửi email thông báo tới {recipient_email}")
        return True
    
    except Exception as e:
        print(f"Lỗi khi gửi email: {e}")
        return False