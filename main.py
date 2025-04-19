from dilithium import Dilithium, Dilithium2, Dilithium3, Dilithium5
import os
import hashlib
from PyPDF2 import PdfReader, PdfWriter

def key_gen():
    # Tạo đối tượng Dilithium với bộ tham số Dilithium3
    dilithium = Dilithium3  # Sử dụng Dilithium3 (hoặc Dilithium2, Dilithium5 tùy nhu cầu)

    # Tạo cặp khóa public và private
    pk, sk = dilithium.keygen()

    # Đường dẫn thư mục lưu khóa
    key_dir = "./key"
    os.makedirs(key_dir, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

    # Lưu public key
    public_key_path = os.path.join(key_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(pk)
    print(f"Public key saved to {public_key_path}")

    # Lưu private key
    private_key_path = os.path.join(key_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(sk)
    print(f"Private key saved to {private_key_path}")

def sign_pdf(private_key_path, input_pdf_path):
    """
    Ký file PDF bằng private key và lưu file đã ký vào thư mục 'signed'.
    """
    # Tạo tên file đầu ra bằng cách thay '.pdf' bằng '_signed.pdf'
    if input_pdf_path.endswith(".pdf"):
        output_pdf_name = os.path.basename(input_pdf_path)[:-4] + "_signed.pdf"
    else:
        output_pdf_name = os.path.basename(input_pdf_path) + "_signed.pdf"

    # Đường dẫn thư mục lưu file đã ký
    output_dir = "D:\\source_code\\python\\dilithium\\signed"
    os.makedirs(output_dir, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

    # Đường dẫn file đầu ra
    output_pdf_path = os.path.join(output_dir, output_pdf_name)

    # Đọc private key từ file
    with open(private_key_path, "rb") as f:
        sk = f.read()

    # Đọc toàn bộ dữ liệu nhị phân của file PDF
    with open(input_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Tạo hash từ toàn bộ dữ liệu nhị phân của file PDF
    pdf_hash = hashlib.sha256(pdf_bytes).digest()

    # Ký hash bằng private key
    dilithium = Dilithium3  # Sử dụng Dilithium3
    signature = dilithium.sign(sk, pdf_hash)

    # Lưu chữ ký vào metadata
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({
        "/Signature": signature.hex()  # Lưu chữ ký với key "/Signature"
    })

    # Lưu file PDF đã ký
    with open(output_pdf_path, "wb") as f:
        writer.write(f)

    print(f"PDF đã được ký và lưu tại: {output_pdf_path}")


def verify_pdf(public_key_path, signed_pdf_path):
    """
    Xác minh chữ ký của file PDF bằng public key.
    """
    # Đọc public key từ file
    with open(public_key_path, "rb") as f:
        pk = f.read()

    # Đọc toàn bộ dữ liệu nhị phân của file PDF
    with open(signed_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    # Tạo hash từ toàn bộ dữ liệu nhị phân của file PDF
    pdf_hash = hashlib.sha256(pdf_bytes).digest()

    # Lấy chữ ký từ metadata
    reader = PdfReader(signed_pdf_path)
    metadata = reader.metadata
    signature_hex = metadata.get("/Signature", None)  # Sử dụng key "/Signature"
    if not signature_hex:
        print("Không tìm thấy chữ ký trong file PDF.")
        return False

    # Chuyển đổi chữ ký từ hex sang bytes
    signature = bytes.fromhex(signature_hex)

    # Xác minh chữ ký
    dilithium = Dilithium3  # Sử dụng Dilithium3
    is_valid = dilithium.verify(pk, pdf_hash, signature)

    if is_valid:
        print("Chữ ký hợp lệ.")
    else:
        print("Chữ ký không hợp lệ.")
    return is_valid

while True:
    print("Nhập số tương ứng với phương thức: ")
    print("1. Tạo khóa")
    print("2. Ký văn bản")
    print("3. Xác minh văn bản")
    print("4. Thoát")
    try:
        n = int(input("Lựa chọn của bạn: "))
        if n == 1:
            # Tạo khóa
            key_gen()
        elif n == 2:
            # Ký văn bản
            input_pdf = input("Nhập đường dẫn file PDF cần ký: ")
            private_key_path = "./key/private_key.pem"
            sign_pdf(private_key_path, input_pdf)
        elif n == 3:
            # Xác minh văn bản
            signed_pdf = input("Nhập đường dẫn file PDF đã ký: ")
            public_key_path = "./key/public_key.pem"
            verify_pdf(public_key_path, signed_pdf)
        elif n == 4:
            # Thoát chương trình
            print("Thoát chương trình.")
            break
        else:
            print("Lựa chọn không hợp lệ. Vui lòng nhập lại.")
    except ValueError:
        print("Vui lòng nhập một số hợp lệ.")
