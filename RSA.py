from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os


# Geração de chaves RSA
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Salvar chave em arquivo
def save_key_to_file(key, filename, is_private=False):
    file_path = os.path.join( filename)
    with open(file_path, "wb") as file:
        if is_private:
            file.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        else:
            file.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

# Carregar chave privada de arquivo
def load_private_key_from_file(filename):
    file_path = os.path.join( filename)
    with open(file_path, "rb") as file:
        return serialization.load_pem_private_key(file.read(), password=None)

# Carregar chave pública de arquivo
def load_public_key_from_file(filename):
    file_path = os.path.join( filename)
    with open(file_path, "rb") as file:
        return serialization.load_pem_public_key(file.read())

# Criptografar dados usando a chave pública
def encrypt_data(public_key, data):
    ciphertext = public_key.encrypt(
        data.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext

# Descriptografar dados usando a chave privada
def decrypt_data(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    # Gerar chaves
    private_key, public_key = generate_keys()

    # Salvar as chaves em arquivos
    save_key_to_file(private_key, "private_key.pem", is_private=True)
    save_key_to_file(public_key, "public_key.pem")

    # Carregar as chaves dos arquivos
    loaded_private_key = load_private_key_from_file("private_key.pem")
    loaded_public_key = load_public_key_from_file("public_key.pem")

    # Dados para criptografar
    message = "Textinho que vai ser criptografado uhul"

    # Criptografar os dados
    encrypted_message = encrypt_data(loaded_public_key, message)
    print("Mensagem criptografada:", encrypted_message)

    # Descriptografar os dados
    decrypted_message = decrypt_data(loaded_private_key, encrypted_message)
    print("\n\nMensagem descriptografada:", decrypted_message)
