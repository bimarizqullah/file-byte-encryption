import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

# ===== Caesar Cipher =====

def caesar_encrypt_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)

def caesar_decrypt_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)

# ===== Vigenère Cipher =====

def vigenere_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes((b + key[i % key_len]) % 256 for i, b in enumerate(data))

def vigenere_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes((b - key[i % key_len]) % 256 for i, b in enumerate(data))

# ===== AES Layer (CBC) =====

def derive_aes_key(key_str: str) -> bytes:
    return hashlib.sha256(key_str.encode()).digest()

def aes_encrypt_bytes(data: bytes, key_str: str) -> bytes:
    key = derive_aes_key(key_str)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted

def aes_decrypt_bytes(data: bytes, key_str: str) -> bytes:
    key = derive_aes_key(key_str)
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

# ===== AES Layer (CFB) =====

def aes_cfb_encrypt_bytes(data: bytes, key_str: str) -> bytes:
    key = derive_aes_key(key_str)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = cipher.encrypt(data)
    return iv + encrypted

def aes_cfb_decrypt_bytes(data: bytes, key_str: str) -> bytes:
    key = derive_aes_key(key_str)
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(encrypted_data)

# ===== Combined Encryption/Decryption =====

def get_caesar_shift_from_key(key: str) -> int:
    return len(key) % 256

def encrypt_data(data: bytes, key: str) -> bytes:
    shift = get_caesar_shift_from_key(key)
    caesar = caesar_encrypt_bytes(data, shift)
    vigenere = vigenere_encrypt_bytes(caesar, key.encode())
    aes_cbc = aes_encrypt_bytes(vigenere, key)
    aes_cfb = aes_cfb_encrypt_bytes(aes_cbc, key)
    return aes_cfb

def decrypt_data(data: bytes, key: str) -> bytes:
    shift = get_caesar_shift_from_key(key)
    aes_cbc = aes_cfb_decrypt_bytes(data, key)
    vigenere = aes_decrypt_bytes(aes_cbc, key)
    caesar = vigenere_decrypt_bytes(vigenere, key.encode())
    return caesar_decrypt_bytes(caesar, shift)

# ===== Encrypt Filename =====

def encrypt_filename(name: str, key: str) -> str:
    encrypted = encrypt_data(name.encode(), key)
    return encrypted.hex()

def decrypt_filename(encrypted_hex: str, key: str) -> str:
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted = decrypt_data(encrypted_bytes, key)
        return decrypted.decode(errors="ignore")
    except:
        return "unknown_filename"

# ===== Streamlit App =====

st.set_page_config(page_title="Byte File Encryptor", layout="centered")
st.title("🔐 Byte File Encryptor & Decryptor (Caesar + Vigenère + AES-CBC + AES-CFB)")
st.markdown("🔒 Enkripsi file dengan nama acak dan kembalikan nama asli saat dekripsi!")

mode = st.radio("Mode", ["Enkripsi", "Dekripsi"])
uploaded_file = st.file_uploader("📂 Unggah file", type=None)
key = st.text_input("🔑 Kunci Enkripsi (digunakan untuk semua metode)", placeholder="Masukkan kunci")

if uploaded_file and key:
    file_data = uploaded_file.read()
    filename = uploaded_file.name

    if st.button("🔄 Proses"):
        try:
            if mode == "Enkripsi":
                # Ambil nama asli
                if "." in filename:
                    name, ext = filename.rsplit(".", 1)
                    original_fullname = f"{name}.{ext}"
                else:
                    original_fullname = filename

                # Tambahkan metadata nama
                name_bytes = original_fullname.encode()
                name_len = len(name_bytes)
                metadata = bytes([name_len]) + name_bytes

                # Enkripsi isi
                encrypted_content = encrypt_data(file_data, key)
                result = metadata + encrypted_content

                # Nama acak
                encrypted_name = encrypt_filename(original_fullname, key)
                output_filename = f"{encrypted_name}.bin"

                st.success("✅ File berhasil dienkripsi!")

            else:
                # Ambil nama asli dari metadata
                name_len = file_data[0]
                name_bytes = file_data[1:1+name_len]
                original_filename = name_bytes.decode(errors="ignore")

                # Dekripsi isi
                encrypted_data = file_data[1+name_len:]
                result = decrypt_data(encrypted_data, key)

                # Format nama file hasil dekripsi
                if "." in original_filename:
                    name, ext = original_filename.rsplit(".", 1)
                    output_filename = f"{name}_decrypted.{ext}"
                else:
                    output_filename = f"{original_filename}_decrypted.bin"

                st.success(f"✅ File berhasil didekripsi sebagai `{output_filename}`")

                # Jika file audio, tampilkan preview
                if output_filename.endswith(("mp3", "wav", "ogg")):
                    st.audio(result, format=f"audio/{ext}")

            # Tombol unduh
            st.download_button("⬇️ Unduh File Hasil", result, file_name=output_filename)

        except Exception as e:
            st.error(f"❌ Terjadi kesalahan: {e}")
else:
    st.info("📂 Unggah file dan isi semua parameter untuk melanjutkan.")
