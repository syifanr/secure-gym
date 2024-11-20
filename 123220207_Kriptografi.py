import streamlit as st
import hashlib
import sqlite3
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image, ImageDraw, ImageFont
import io
import numpy as np 
from arc4 import ARC4

# Fungsi hashing untuk password
def hash_password(password):
    salt = "random_salt"
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Database setup
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # Table for user accounts
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    # Table for gym bookings
    c.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            full_name TEXT,
            membership_type TEXT,
            booking_time TEXT,
            booking_date TEXT,
            price INTEGER,
            encrypted_info TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Table for encryption keys
    c.execute("""
        CREATE TABLE IF NOT EXISTS encryption_keys (
            booking_id INTEGER PRIMARY KEY,
            encryption_key TEXT,
            FOREIGN KEY (booking_id) REFERENCES bookings (id)
        )
    """)
    # Table for completed bookings
    c.execute("""
        CREATE TABLE IF NOT EXISTS completed_bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            full_name TEXT,
            membership_type TEXT,
            booking_time TEXT,
            booking_date TEXT,
            encrypted_info TEXT,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Register user
def register_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

# Fungsi validasi password
def validate_password(password):
    if len(password) < 8:
        return "Password harus memiliki minimal 8 karakter."
    if not any(char.isupper() for char in password):
        return "Password harus memiliki setidaknya satu huruf kapital."
    if not any(char.isdigit() for char in password):
        return "Password harus memiliki setidaknya satu angka."
    return None

# Login user
def login_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user


# Function to register a user
def register_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

# Function to check if user exists
def login_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user

# Menyimpan User yang Berhasil Register
def get_registered_users():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = c.fetchall()
    conn.close()
    return [user[0] for user in users]

# Hapus Data User
def delete_user(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

# Function to save booking
def save_booking(username, booking_time, booking_date, encrypted_info):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO bookings (username, booking_time, booking_date, encrypted_info)
        VALUES (?, ?, ?, ?)
    """, (username, booking_time, booking_date, encrypted_info))
    conn.commit()
    booking_id = c.lastrowid
    conn.close()
    return booking_id

# Function to save encryption key
def save_encryption_key(booking_id, encryption_key):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO encryption_keys (booking_id, encryption_key) VALUES (?, ?)", (booking_id, encryption_key))
    conn.commit()
    conn.close()

# Function to get all bookings
def get_all_bookings():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # Pastikan kolom 'price' disertakan dalam query
    c.execute("""
        SELECT id, username, booking_time, booking_date, price, encrypted_info, full_name, membership_type
        FROM bookings
    """)
    bookings = c.fetchall()
    conn.close()
    return bookings


# Function to get encryption keys
def get_encryption_keys():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        SELECT b.id, b.username, b.booking_time, b.booking_date, ek.encryption_key 
        FROM bookings b
        JOIN encryption_keys ek ON b.id = ek.booking_id
    """)
    keys = c.fetchall()
    conn.close()
    return keys

# Fungsi ROT13 manual
def rot13_manual(text):
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)

# Fungsi enkripsi: ROT13 manual diikuti dengan AES
def encrypt_info_rot13_aes(data, aes_key):
    # ROT13 manual
    rot13_encrypted = rot13_manual(data)
    
    # Enkripsi AES
    aes_key = aes_key.encode()[:16]  # Pastikan kunci 16 byte
    iv = get_random_bytes(16)  # Inisialisasi vektor acak
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Padding data sesuai ukuran blok AES
    padded_data = pad(rot13_encrypted.encode(), AES.block_size)
    encrypted_data = iv + cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode()  # Kembalikan sebagai string base64

# Fungsi dekripsi: AES diikuti dengan ROT13
def decrypt_info_rot13_aes(encrypted_data, aes_key):
    try:
        # Dekripsi data AES
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        aes_key = aes_key.encode()[:16]  # Pastikan kunci 16 byte
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data[16:])
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        # Decode ROT13 manual
        rot13_decrypted = rot13_manual(decrypted_data.decode())

        formatted_result = rot13_decrypted.replace("User:", "\n- Username:")
        formatted_result = formatted_result.replace("Full Name:", "Nama Lengkap:")
        formatted_result = formatted_result.replace("Membership:", "Jenis Keanggotaan:")
        formatted_result = formatted_result.replace("Booking Date:", "Tanggal Pemesanan:")

        # Format harga dan pindahkan ke paling bawah
        if "Price:" in formatted_result:
            price_line = [line for line in formatted_result.split(", ") if "Price:" in line][0]
            price_value = price_line.split(":")[1].strip()
            price_formatted = f"Harga: Rp {int(price_value):,}".replace(",", ".")
            formatted_result = formatted_result.replace(f", {price_line}", "")
            formatted_result += f"\n- {price_formatted}"

        formatted_result = formatted_result.replace(", ", "\n- ")

        return formatted_result

    except Exception as e:
        return f"Kunci tidak sesuai!"



# Menyelesaikan Pesanan
def complete_booking(booking_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Ambil detail pesanan dari bookings
    c.execute("""
        SELECT username, booking_time, booking_date, encrypted_info, full_name, membership_type
        FROM bookings WHERE id = ?
    """, (booking_id,))
    booking = c.fetchone()

    if booking:
        username, booking_time, booking_date, encrypted_info, full_name, membership_type = booking
        # Masukkan data ke tabel completed_bookings
        c.execute("""
            INSERT INTO completed_bookings (username, booking_time, booking_date, encrypted_info, full_name, membership_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, booking_time, booking_date, encrypted_info, full_name, membership_type))

        # Hapus dari tabel bookings
        c.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
        conn.commit()

    conn.close()


# Daftar Pesanan
def get_all_completed_bookings():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT id, username, full_name, booking_time, booking_date, encrypted_info FROM completed_bookings")
    completed_bookings = c.fetchall()
    conn.close()
    return completed_bookings

# Menghapus Daftar Pesanan
def delete_booking(booking_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    conn.commit()
    conn.close()

def update_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Periksa kolom di tabel bookings
    c.execute("PRAGMA table_info(bookings)")
    columns = [column[1] for column in c.fetchall()]
    if "price" not in columns:
        c.execute("ALTER TABLE bookings ADD COLUMN price INTEGER")
    if "full_name" not in columns:
        c.execute("ALTER TABLE bookings ADD COLUMN full_name TEXT")
    if "membership_type" not in columns:
        c.execute("ALTER TABLE bookings ADD COLUMN membership_type TEXT")

    # Periksa kolom di tabel completed_bookings
    c.execute("PRAGMA table_info(completed_bookings)")
    completed_columns = [column[1] for column in c.fetchall()]
    if "full_name" not in completed_columns:
        c.execute("ALTER TABLE completed_bookings ADD COLUMN full_name TEXT")
    if "membership_type" not in completed_columns:
        c.execute("ALTER TABLE completed_bookings ADD COLUMN membership_type TEXT")

    conn.commit()
    conn.close()


def update_completed_bookings_table():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Periksa apakah kolom ada di tabel
    c.execute("PRAGMA table_info(completed_bookings)")
    columns = [column[1] for column in c.fetchall()]
    
    # Tambahkan kolom hanya jika belum ada
    if "full_name" not in columns:
        c.execute("ALTER TABLE completed_bookings ADD COLUMN full_name TEXT")
    if "membership_type" not in columns:
        c.execute("ALTER TABLE completed_bookings ADD COLUMN membership_type TEXT")

    conn.commit()
    conn.close()


def reset_completed_bookings():
    """
    Menghapus semua data di tabel completed_bookings dan mereset ID mulai dari 1.
    """
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        # Hapus semua data di tabel completed_bookings
        c.execute("DELETE FROM completed_bookings")

        # Reset autoincrement ID
        c.execute("DELETE FROM sqlite_sequence WHERE name='completed_bookings'")

        conn.commit()
        conn.close()
        return "Riwayat pesanan berhasil dihapus dan ID dimulai dari 1 kembali."
    except sqlite3.Error as e:
        return f"Kesalahan database: {str(e)}"


# Perbarui fungsi save_booking agar menerima full_name dan membership_type
def save_booking(username, full_name, membership_type, booking_time, booking_date, price, encrypted_info):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO bookings (username, full_name, membership_type, booking_time, booking_date, price, encrypted_info)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, full_name, membership_type, booking_time, booking_date, price, encrypted_info))
    conn.commit()
    booking_id = c.lastrowid
    conn.close()
    return booking_id

def display_bookings(bookings, is_completed=False):
    for booking in bookings:
        if is_completed:
            booking_id, username, booking_time, booking_date, encrypted_info, full_name, membership_type = booking
        else:
            booking_id, username, booking_time, booking_date, encrypted_info, full_name, membership_type = booking

        with st.expander(f"Pesanan ID {booking_id} - {username}"):
            st.write(f"**Nama Lengkap:** {full_name}")
            st.write(f"**Keanggotaan:** {membership_type}")
            st.write(f"**Info Terenkripsi:** {encrypted_info}")
            decryption_key = st.text_input(f"Kunci Dekripsi untuk Pesanan ID {booking_id}", key=f"decrypt_key_{booking_id}")
            if st.button(f"Dekripsi Pesanan ID {booking_id}", key=f"decrypt_button_{booking_id}"):
                decrypted_info = decrypt_info_rot13_aes(encrypted_info, decryption_key)
                st.write(f"**Hasil Dekripsi:** {decrypted_info}")

            if not is_completed:
                col1, col2 = st.columns([1, 1])

                # Status untuk menyelesaikan pesanan
                complete_key = f"complete_{booking_id}"
                delete_key = f"delete_{booking_id}"

                # Inisialisasi state untuk confirm box
                if complete_key not in st.session_state:
                    st.session_state[complete_key] = False
                if delete_key not in st.session_state:
                    st.session_state[delete_key] = False

                # Tombol untuk menyelesaikan pesanan
                with col1:
                    if not st.session_state[complete_key]:  # Jika belum memunculkan selectbox
                        if st.button(f"Selesaikan Pesanan ID {booking_id}", key=f"button_{complete_key}"):
                            st.session_state[complete_key] = True
                    else:
                        confirm = st.selectbox(
                            f"Apakah Anda yakin ingin menyelesaikan pesanan ID {booking_id}?",
                            ["Pilih Opsi", "Ya", "Tidak"],
                            key=f"select_{complete_key}"
                        )
                        if confirm == "Ya":
                            try:
                                complete_booking(booking_id)
                                st.success(f"Pesanan ID {booking_id} telah diselesaikan dan dipindahkan ke riwayat.")
                            except Exception as e:
                                st.error(f"Terjadi kesalahan saat menyelesaikan pesanan ID {booking_id}: {str(e)}")
                        elif confirm == "Tidak":
                            st.session_state[complete_key] = False
                            st.warning(f"Pesanan ID {booking_id} tidak jadi diselesaikan.")

                # Tombol untuk menghapus pesanan
                with col2:
                    if not st.session_state[delete_key]:  # Jika belum memunculkan selectbox
                        if st.button(f"Hapus Pesanan ID {booking_id}", key=f"button_{delete_key}"):
                            st.session_state[delete_key] = True
                    else:
                        confirm = st.selectbox(
                            f"Apakah Anda yakin ingin menghapus pesanan ID {booking_id}?",
                            ["Pilih Opsi", "Ya", "Tidak"],
                            key=f"select_{delete_key}"
                        )
                        if confirm == "Ya":
                            try:
                                delete_booking(booking_id)
                                st.success(f"Pesanan ID {booking_id} berhasil dihapus!")
                            except Exception as e:
                                st.error(f"Terjadi kesalahan saat menghapus pesanan ID {booking_id}: {str(e)}")
                        elif confirm == "Tidak":
                            st.session_state[delete_key] = False
                            st.warning(f"Pesanan ID {booking_id} tidak jadi dihapus.")

# Fungsi untuk membuat kartu member
def generate_member_card(full_name, membership_type, booking_date, booking_time):
    # Template ukuran kartu
    width, height = 600, 400
    card = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(card)

    # Font untuk teks utama
    try:
        main_font = ImageFont.truetype("arial.ttf", 40)  # Gunakan font Arial
        text_font = ImageFont.truetype("arial.ttf", 20)
    except IOError:
        main_font = ImageFont.load_default()  # Gunakan default jika Arial tidak ditemukan
        text_font = ImageFont.load_default()

    # Tambahkan teks utama di tengah kartu
    main_text = "KARTU MEMBER GYM"
    text_bbox = draw.textbbox((0, 0), main_text, font=main_font)  # Menggunakan textbbox
    text_width, text_height = text_bbox[2] - text_bbox[0], text_bbox[3] - text_bbox[1]
    draw.text(((width - text_width) / 2, 50), main_text, fill="black", font=main_font)

    # Tambahkan detail lainnya
    draw.text((50, 150), f"Nama: {full_name}", fill="black", font=text_font)
    draw.text((50, 200), f"Jenis Keanggotaan: {membership_type}", fill="black", font=text_font)
    draw.text((50, 250), f"Tanggal Pemesanan: {booking_date}", fill="black", font=text_font)
    draw.text((50, 300), f"Waktu Pemesanan: {booking_time}", fill="black", font=text_font)

    # Tambahkan garis tepi
    draw.rectangle([(0, 0), (width - 1, height - 1)], outline="black", width=3)

    return card



# Fungsi untuk mengunduh file kartu member
def download_card_as_image(card, filename="member_card.png"):
    buf = io.BytesIO()
    card.save(buf, format="PNG")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    button_html = f"""
        <style>
        .download-button {{
            display: inline-block;
            padding: 10px 20px;
            font-size: 16px;
            font-weight: bold;
            color: white;
            background-color: #4CAF50;
            text-align: center;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .download-button:hover {{
            background-color: #45a049;
        }}
        </style>
        <a href="data:image/png;base64,{b64}" download="{filename}" class="download-button">Unduh Kartu Member</a>
    """
    return button_html


# Fungsi untuk menyembunyikan teks dalam gambar
def hide_text_in_image(image, text):
    data = text + "###END###"  # Tanda akhir data
    bin_data = ''.join(format(ord(char), '08b') for char in data)
    
    # Convert image to numpy array
    img_array = np.array(image)
    flat_img = img_array.flatten()

    if len(bin_data) > len(flat_img):
        raise ValueError("Teks terlalu besar untuk disisipkan dalam gambar!")

    for i in range(len(bin_data)):
        flat_img[i] = (flat_img[i] & ~1) | int(bin_data[i])

    reshaped_img = flat_img.reshape(img_array.shape)
    return Image.fromarray(reshaped_img.astype('uint8'))

# Fungsi untuk mengambil teks tersembunyi dari gambar
def retrieve_text_from_image(image):
    img_array = np.array(image).flatten()
    bin_data = [str(pixel & 1) for pixel in img_array[:len(img_array)]]
    byte_array = [''.join(bin_data[i:i+8]) for i in range(0, len(bin_data), 8)]
    chars = [chr(int(byte, 2)) for byte in byte_array]
    text = ''.join(chars)
    end_marker = "###END###"
    if end_marker in text:
        return text[:text.index(end_marker)]
    return "Data tidak ditemukan."

def rc4_crypt(data, key):
    """Sederhana implementasi RC4 untuk enkripsi/dekripsi."""
    S = list(range(256))
    j = 0
    out = []

    # Key scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

# Fungsi Enkripsi dan Dekripsi File
def encrypt_with_rc4(data, key):
    return rc4_crypt(data, key.encode())

def decrypt_with_rc4(encrypted_data, key):
    return rc4_crypt(encrypted_data, key.encode())

def reset_bookings():
    """
    Menghapus semua data di tabel bookings dan completed_bookings, serta mereset ID auto-increment.
    """
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        # Hapus semua data di tabel bookings dan reset ID
        c.execute("DELETE FROM bookings")
        c.execute("DELETE FROM sqlite_sequence WHERE name='bookings'")

        # Hapus semua data di tabel completed_bookings dan reset ID
        c.execute("DELETE FROM completed_bookings")
        c.execute("DELETE FROM sqlite_sequence WHERE name='completed_bookings'")

        conn.commit()
        conn.close()
        return "Semua data pesanan berhasil dihapus dan ID telah direset."
    except sqlite3.Error as e:
        return f"Kesalahan database: {str(e)}"

# Initialize database
init_db()

# Session state to handle login status
if "login_status" not in st.session_state:
    st.session_state["login_status"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

# Main Application
if st.session_state["login_status"] is None:  # Not logged in
    st.sidebar.title("Menu")
    menu = st.sidebar.radio("Pilih Menu", ["Dashboard", "Login", "Register"])

    if menu == "Dashboard":
        st.title("Selamat Datang di Secure App - Sistem Pemesanan Gym")
        st.image(
            "https://png.pngtree.com/background/20230516/original/pngtree-large-room-full-of-equipment-in-a-gym-picture-image_2611111.jpg",
            use_column_width=True,
        )
        st.markdown("""
        **Pada aplikasi ini menyediakan layanan:**
        - Pemesanan Tempat Gym yang sudah terenkripsi dengan keamanan tinggi.
        - Pengiriman pesan secara rahasia
        - Fitur Enkripsi dan Dekripsi yang aman. 
        """) 
        st.markdown("""
        **Langkah Penggunaan Aplikasi:**          
        - Registrasi jika anda pengguna baru.
        - Login sebagai Customer untuk melakukan pemesanan gym.
        - Lakukan Pemesanan sesuai dengan kebutuhan.
        """)      
    elif menu == "Login":
        st.title("Login")
        role = st.selectbox("Login sebagai", ["Admin", "Customer"])
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            if role == "Admin":
                if username == "admin" and password == "admin123":  # Password admin
                    st.success("Login Admin berhasil!")
                    st.session_state["login_status"] = "logged_in"
                    st.session_state["role"] = "Admin"
                    st.session_state["user"] = username
                else:
                    st.error("Username atau password admin salah.")
            else:  # Login sebagai Customer
                hashed_password = hash_password(password)
                user = login_user(username, hashed_password)
                if user:
                    st.success(f"Selamat datang, {username}!")
                    st.session_state["login_status"] = "logged_in"
                    st.session_state["role"] = "Customer"
                    st.session_state["user"] = username  # Tambahkan ini untuk menyimpan username
                else:
                    st.error("Username atau password salah.")


    elif menu == "Register":
        st.title("Register")
        new_username = st.text_input("Username Pengguna Baru")
        new_password = st.text_input("Password Baru", type="password")
        confirm_password = st.text_input("Konfirmasi Password", type="password")
        
        if st.button("Register"):
            if new_password != confirm_password:
                st.error("Password tidak sesuai!")
            else:
                validation_message = validate_password(new_password)
                if validation_message:
                    st.error(validation_message)
                else:
                    try:
                        hashed_password = hash_password(new_password)
                        register_user(new_username, hashed_password)
                        st.success("Registrasi berhasil! Silakan login ulang.")
                    except sqlite3.IntegrityError:
                        st.error("Username sudah digunakan.")

else:  # Logged in
    if st.session_state["role"] == "Admin":
        st.title("Admin Panel")
        st.sidebar.title("Dashboard Admin")
        st.sidebar.write("Selamat datang kembali, Admin!")
        admin_action = st.sidebar.radio("Navigasi", ["Kelola Pengguna", "Dekripsi Pesan Gambar Member", "Dekripsi File Pembayaran", "Logout"])
        if admin_action == "Kelola Pengguna":
            users = get_registered_users()
            if users:
                st.subheader("Daftar Pengguna Terdaftar:")
                for idx, user in enumerate(users, start=1):
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"{idx}. {user}")
                    with col2:
                        if st.button(f"Hapus {user}", key=f"delete_{user}"):
                            delete_user(user)
                            st.success(f"Username '{user}' berhasil dihapus!")
            else:
                st.warning("Belum ada pengguna yang terdaftar.")


            # Bagian Daftar Pesanan
            st.subheader("Daftar Pesanan")
            bookings = get_all_bookings()
            if bookings:
                for booking in bookings:
                    # Ambil data dari hasil query
                    booking_id, username, booking_time, booking_date, price, encrypted_info, full_name, membership_type = booking
                    with st.expander(f"Pesanan #{booking_id} - {username}"):
                        st.write(f"**Info Terenkripsi:** {encrypted_info}")
                        decryption_key = st.text_input(f"Kunci Dekripsi untuk Pesanan ID {booking_id}", key=f"decrypt_key_{booking_id}")
                        if st.button(f"Dekripsi Pesanan ID {booking_id}", key=f"decrypt_button_{booking_id}"):
                            decrypted_info = decrypt_info_rot13_aes(encrypted_info, decryption_key)
                            st.write(f"**Hasil Dekripsi:** {decrypted_info}")

                        # Opsi untuk menyelesaikan atau menghapus pesanan
                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if st.button(f"Selesaikan Pesanan ID {booking_id}", key=f"complete_{booking_id}"):
                                complete_booking(booking_id)
                                st.success(f"Pesanan ID {booking_id} telah diselesaikan dan dipindahkan ke riwayat.")
                        with col2:
                            if st.button(f"Hapus Pesanan ID {booking_id}", key=f"delete_booking_{booking_id}"):
                                delete_booking(booking_id)
                                st.success(f"Pesanan ID {booking_id} berhasil dihapus!")
            else:
                st.warning("Belum ada data pesanan.")

            # Bagian Daftar Pesanan yang Diselesaikan (Riwayat Pesanan)
            st.subheader("Riwayat Pesanan")
            completed_bookings = get_all_completed_bookings()
            if completed_bookings:
                for completed_booking in completed_bookings:
                    booking_id, username, full_name, booking_time, booking_date, encrypted_info = completed_booking
                    with st.expander(f"Pesanan #{booking_id} - {username} (Selesai)"):
                        st.write(f"**Nama Lengkap:** {full_name}")
                        st.write(f"**Waktu Pemesanan:** {booking_time}")
                        st.write(f"**Tanggal Pemesanan:** {booking_date}")
            else:
                st.warning("Belum ada riwayat pesanan.")
            
            if st.button("Bersihkan Semua Data Pesanan"):
                result = reset_bookings()
                if "berhasil" in result.lower():
                    st.success(result)
                else:
                    st.error(result)
            
        elif admin_action == "Dekripsi Pesan Gambar Member":
            st.subheader("Melihat pesan yang telah dikirim dengan Kartu Member")
            uploaded_image = st.file_uploader("Upload Gambar Kartu Member dengan Pesan", type=["png", "jpg", "jpeg"])
            if st.button("Dekripsi Pesan"):
                if uploaded_image:
                    image = Image.open(uploaded_image).convert("RGB")
                    hidden_message = retrieve_text_from_image(image)
                    st.write(f"Pesan yang Dikirim: {hidden_message}")

        elif admin_action == "Dekripsi File Pembayaran":
            st.subheader("Dekripsi File Pembayaran")
            
            uploaded_file = st.file_uploader("Upload file terenkripsi", type=["bin", "enc", "txt", "pdf", "docx"])
            rc4_key = st.text_input("Masukkan Kunci RC4 (3-4 Karakter)")
            
            if st.button("Dekripsi File"):
                if uploaded_file and rc4_key:
                    if len(rc4_key) < 3 or len(rc4_key) > 4:
                        st.error("Kunci RC4 harus antara 3 hingga 4 karakter.")
                    else:
                        try:
                            encrypted_data = uploaded_file.read()  # Membaca data file
                            decrypted_data = decrypt_with_rc4(encrypted_data, rc4_key)  # Dekripsi dengan RC4

                            # Simpan file didekripsi
                            decrypted_file_name = f"decrypted_{uploaded_file.name.split('_', 1)[-1]}"
                            with open(decrypted_file_name, "wb") as f:
                                f.write(decrypted_data)

                            # Menampilkan opsi unduh
                            st.success("File berhasil didekripsi!")
                            st.download_button(
                                label="Unduh File Didekripsi",
                                data=decrypted_data,
                                file_name=decrypted_file_name,
                                mime="application/octet-stream",
                            )
                        except Exception as e:
                            st.error(f"Terjadi kesalahan saat mendekripsi: {str(e)}")
                else:
                    st.error("Harap unggah file dan masukkan kunci RC4!")
            

        elif admin_action == "Logout":
            st.session_state["login_status"] = None
            st.session_state["role"] = None
            st.session_state["user"] = None  # Reset user
            st.success("Berhasil logout!")

    elif st.session_state["role"] == "Customer":
        username = st.session_state.get("username")
        st.title(f"Selamat Datang di Secure App - Sistem Pemesanan Gym!")
        st.sidebar.title("Customer Panel")
        customer_action = st.sidebar.radio("Navigasi", ["Pemesanan Tempat Gym", "Kirim Pesan Gambar Kartu Member", "Kirim File Detail Pemesanan", "Logout"])
        
        if customer_action == "Pemesanan Tempat Gym":
            st.image(
                "https://e1.pxfuel.com/desktop-wallpaper/217/624/desktop-wallpaper-gym-muscular.jpg",
                use_column_width=True,
            )
            st.subheader("Silahkan Lakukan Pemesanan Sesuai Kebutuhan")

            # Input data pemesanan
            full_name = st.text_input("Masukkan Nama Lengkap Anda")
            booking_time = st.time_input("Waktu Pemesanan")
            booking_date = st.date_input("Tanggal Pemesanan")
            membership_type = st.selectbox("Pilih Jenis Keanggotaan", ["Guest 1 Hari", "Member 1 Bulan", "Member 6 Bulan", "Member 1 Tahun"])
            membership_options = {
                "Guest 1 Hari": 20000,
                "Member 1 Bulan": 250000,
                "Member 6 Bulan": 1100000,
                "Member 1 Tahun": 2000000
            }
            price = membership_options[membership_type]
            st.write(f"**Total Harga:** Rp {price:,.0f}".replace(",", "."))

            aes_key = st.text_input("Masukkan Kunci AES 16 Karakter secara Presisi (Tidak Lebih/Tidak Kurang)")

            # Validasi input
            if st.button("Buat Pesanan"):
                if not full_name:
                    st.error("Nama lengkap tidak boleh kosong.")
                elif not booking_time:
                    st.error("Waktu pemesanan tidak boleh kosong.")
                elif not booking_date:
                    st.error("Tanggal pemesanan tidak boleh kosong.")
                elif not aes_key:
                    st.error("Kunci AES tidak boleh kosong.")
                elif len(aes_key) != 16:
                    st.error("Kunci AES harus tepat 16 karakter.")
                else:
                    # Semua validasi terpenuhi
                    booking_info = f"User: {st.session_state['user']}, Full Name: {full_name}, Membership: {membership_type}, Price: {price}, Booking Time: {booking_time}, Booking Date: {booking_date}"
                    encrypted_info = encrypt_info_rot13_aes(booking_info, aes_key)
                    save_booking(st.session_state["user"], full_name, membership_type, str(booking_time), str(booking_date), price, encrypted_info)
                    st.success("Pesanan berhasil disimpan!")
                    st.write("Info Terenkripsi:", encrypted_info)

                    # Unduh Gambar
                    card = generate_member_card(full_name, membership_type, booking_date, booking_time)
                    st.image(card, use_column_width=False)

                    # Buat file detail pemesanan
                    booking_file_name = f"{full_name.replace(' ', '_')}_Booking_Details.txt"
                    booking_details = f"""
                    Nama: {full_name}
                    Jenis Keanggotaan: {membership_type}
                    Waktu Pemesanan: {booking_time}
                    Tanggal Pemesanan: {booking_date}
                    Harga: Rp {price:,.0f}
                    """.strip()
                    buf_file = io.BytesIO()
                    buf_file.write(booking_details.encode())
                    buf_file.seek(0)

                    # Unduh kartu member
                    buf_card = io.BytesIO()
                    card.save(buf_card, format="PNG")
                    buf_card.seek(0)
                    
                    st.download_button(
                        label="Unduh Kartu Member",
                        data=buf_card,
                        file_name="member_card.png",
                        mime="image/png",
                        key="download_member_card"
                    )

                    st.download_button(
                        label="Unduh Detail Pemesanan",
                        data=buf_file,
                        file_name=booking_file_name,
                        mime="text/plain",
                        key="download_booking_details"
                    )
        
        elif customer_action == "Kirim Pesan Gambar Kartu Member":
            st.write("Upload gambar kartu member:")
            uploaded_image = st.file_uploader("Upload Gambar Kartu Member", type=["png", "jpg", "jpeg"])
            secret_message = st.text_input("Masukkan Pesan Rahasia untuk Disisipkan")
            if st.button("Sisipkan Pesan dan Kirim"):
                if uploaded_image and secret_message:
                    image = Image.open(uploaded_image).convert("RGB")
                    encoded_image = hide_text_in_image(image, secret_message)
                    st.success("Pesan berhasil disisipkan ke dalam gambar.")
                    st.image(encoded_image, use_column_width=False)

                    # Unduh gambar terenkripsi
                    buf = io.BytesIO()
                    encoded_image.save(buf, format="PNG")
                    buf.seek(0)
                    if st.download_button(
                        label="Unduh Gambar dengan Pesan Tersembunyi",
                        data=buf,
                        file_name="encoded_member_card.png",
                        mime="image/png",
                        key="download_encoded_image_button"
                    ):
                        st.success("Gambar berhasil diunduh!")
                else:
                    st.error("Harap masukkan pesan!")

        if customer_action == "Kirim File Detail Pemesanan":
            st.subheader("Enkripsi File Detail Pemesanan")

            uploaded_file = st.file_uploader("Pilih file untuk dienkripsi", type=["pdf", "txt", "docx", "jpg", "png"])
            rc4_key = st.text_input("Masukkan Kunci RC4 (3-4 Karakter)")

            if st.button("Enkripsi dan Kirim"):
                if uploaded_file and rc4_key:
                    if len(rc4_key) < 3 or len(rc4_key) > 4:
                        st.error("Kunci RC4 harus antara 3 hingga 4 karakter.")
                    else:
                        try:
                            file_data = uploaded_file.read()  # Membaca data file
                            encrypted_data = encrypt_with_rc4(file_data, rc4_key)  # Enkripsi dengan RC4

                            # Simpan file terenkripsi
                            encrypted_file_name = f"encrypted_{uploaded_file.name}"
                            with open(encrypted_file_name, "wb") as f:
                                f.write(encrypted_data)

                            # Menampilkan opsi unduh
                            st.success(f"File {uploaded_file.name} berhasil dienkripsi!")
                            st.download_button(
                                label="Unduh File Terenkripsi",
                                data=encrypted_data,
                                file_name=encrypted_file_name,
                                mime="application/octet-stream",
                            )
                        except Exception as e:
                            st.error(f"Terjadi kesalahan saat enkripsi: {str(e)}")
                else:
                    st.error("Harap unggah file dan masukkan kunci RC4!")

        elif customer_action == "Logout":
            st.session_state["login_status"] = None
            st.session_state["role"] = None
            st.session_state["user"] = None  # Reset user
            st.success("Berhasil logout!")

            
