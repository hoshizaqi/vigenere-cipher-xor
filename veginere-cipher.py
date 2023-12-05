def vigenere_encrypt(plaintext, key):
    encrypted_text = ""
    key_stream = generate_key_stream(plaintext, key)
    for i in range(len(plaintext)):
        encrypted_text += chr(ord(plaintext[i]) ^ ord(key_stream[i]))
    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_stream = generate_key_stream(ciphertext, key)
    for i in range(len(ciphertext)):
        decrypted_text += chr(ord(ciphertext[i]) ^ ord(key_stream[i]))
    return decrypted_text

def generate_key_stream(text, key):
    key_stream = ""
    key_length = len(key)
    for i in range(len(text)):
        key_stream += key[i % key_length]
    return key_stream

if __name__ == "__main__":
    key = "IZZAQI"
    plaintext = input('Masukkan plaintext: ')

    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")

    # Enkripsi
    ciphertext = vigenere_encrypt(plaintext, key)
    print(f"Encrypted Text: {ciphertext}")

    # Dekripsi
    decrypted_text = vigenere_decrypt(ciphertext, key)
    print(f"Decrypted Text: {decrypted_text}")
