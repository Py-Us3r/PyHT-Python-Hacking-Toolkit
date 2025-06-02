import ast
import sys
import random
import os

iterations = 6

def get_libraris(file):
    with open(file, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=file)

    imports = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)

    return sorted(imports)


def code_without_libraries(file):
    code = ""
    with open(file, "r", encoding="utf-8") as f_origen:
        for line in f_origen:
            if not line.strip().startswith("import"):
                code += line
    return code


def generate_prime_number():
    def check_if_it_is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True

    while True:
        num = random.randint(1000, 1000000)
        if check_if_it_is_prime(num):
            return num


def random_string(length=30):
    caracters = [chr(random.randint(65, 90)) for _ in range(length // 3)]
    caracters += [chr(random.randint(97, 122)) for _ in range(length - len(caracters))]
    
    random.shuffle(caracters)
    return ''.join(caracters)


def generate_noise():
    operation = ['+', '-', '*', '/']
    func_name = random_string()
    code = f"def {func_name}():\n    result = random.randint(1, 1000)\n"
    
    for _ in range(random.randint(1000,5000)):
        num1 = random.randint(1, 1000)
        num2 = random.randint(1, 1000)
        operation1 = random.choice(operation)
        operation2 = random.choice(operation)
        code += f"    result = ((result {operation1} {num1}) {operation2} {num2})\n"
    
    code += "    return result\n"
    code += f"{func_name}()\n"
    return code


def save_output_into_file(file_name, encripted_content, imports):
    with open(file_name, "w", encoding="utf-8") as f:
        for lib in imports:
            f.write(f"import {lib}\n")
        f.write("import random\n")
        f.write("\n")
        f.write(encripted_content)
        

def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


def extended_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s % b


#--------------------------------------------------------------------------------------------------------------------------


def encryption_metode_1(code_to_encode):
    prime_number = generate_prime_number()
    salt = random.randint(1,300)
    #Encript
    mesage_int = []
    for b in code_to_encode:
        mesage_int.append(ord(b))
    ct = []
    for number in mesage_int:
        ct.append((prime_number * number + salt) % 256)
    encrypted_message = ''.join([hex(i)[2:].zfill(2) for i in ct])
    decryption_func_name = random_string()


    #Generate output
    output_content = ""
    output_content += f"def {decryption_func_name}(prime_number, crypted_msg, salt):\n"
    output_content += "    encryptedlist = [int(crypted_msg[i:i+2], 16) for i in range(0, len(crypted_msg), 2)]\n"
    output_content += "    table = {((prime_number * char + salt) % 256): char for char in range(256)}\n"
    output_content += "    recovery2 = [table.get(num) for num in encryptedlist]\n"
    output_content += "    return bytes(recovery2)\n\n"
    output_content += "if __name__ == \"__main__\":\n"
    output_content += f"    salt = {salt}\n"
    output_content += f"    prime_number = {prime_number}\n"
    output_content += f"    encrypted_message = \"{encrypted_message}\"\n"
    output_content += f"    decrypted_code = {decryption_func_name}(prime_number, encrypted_message, salt).decode('utf-8')\n"
    output_content += "    exec(decrypted_code)\n"
    
    return output_content    


def encryption_metode_2(code_to_encode):
    salt = random.randint(50, 500)
    key = random.randint(10, 250)
    shuffle_key = list(range(256))
    random.shuffle(shuffle_key)
    reverse_key = {v: k for k, v in enumerate(shuffle_key)}
    
    encoded_bytes = bytearray()
    for char in code_to_encode.encode():
        transformed = (shuffle_key[(char ^ key) % 256] + salt) % 256
        encoded_bytes.append(transformed)
    
    encrypted_message = ''.join([hex(i)[2:].zfill(2) for i in encoded_bytes])
    decryption_func_name = random_string()
    
    output_content = ""
    output_content += f"def {decryption_func_name}(encrypted_message, key, salt, reverse_key):\n"
    output_content += "    encrypted_bytes = [int(encrypted_message[i:i+2], 16) for i in range(0, len(encrypted_message), 2)]\n"
    output_content += "    decrypted_bytes = bytearray(reverse_key[(b - salt) % 256] ^ key for b in encrypted_bytes)\n"
    output_content += "    return decrypted_bytes.decode('utf-8')\n\n"
    
    output_content += "if __name__ == \"__main__\":\n"
    output_content += f"    key = {key}\n"
    output_content += f"    salt = {salt}\n"
    output_content += f"    reverse_key = {reverse_key}\n"
    output_content += f"    encrypted_message = \"{encrypted_message}\"\n"
    output_content += f"    decrypted_code = {decryption_func_name}(encrypted_message, key, salt, reverse_key)\n"
    output_content += "    exec(decrypted_code)\n"
    
    return output_content


def encryption_metode_3(code):
    prime1 = generate_prime_number()
    prime2 = generate_prime_number()
    n = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)
    e = 65537
    d = extended_gcd(e, phi)
    
    encrypted_values = [mod_exp(ord(c), e, n) for c in code]
    encrypted_hex = ','.join(str(i) for i in encrypted_values)
    decrypt_func = random_string()
    
    output_code = f"def {decrypt_func}(encrypted, d, n):\n"
    output_code += "    decrypted = ''.join(chr(pow(int(c), d, n)) for c in encrypted.split(','))\n"
    output_code += "    return decrypted\n\n"
    output_code += "if __name__ == \"__main__\":\n"
    output_code += f"    n = {n}\n"
    output_code += f"    e = {e}\n"
    output_code += f"    d = {d}\n"
    output_code += f"    encrypted_code = \"{encrypted_hex}\"\n"
    output_code += f"    decrypted_code = {decrypt_func}(encrypted_code, d, n)\n"
    output_code += "    exec(decrypted_code)\n"
    
    return output_code


def encryption_metode_4(code):
    def random_string():
        return "func_" + ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))

    key = [random.randint(1, 255) for _ in range(16)]
    encrypted_values = [ord(code[i]) ^ key[i % len(key)] for i in range(len(code))]
    encrypted_hex = ','.join(str(i) for i in encrypted_values)
    key_hex = ','.join(str(k) for k in key)
    decrypt_func = random_string()
    output_code = f"def {decrypt_func}(encrypted, key):\n"
    output_code += "    decrypted = ''.join(chr(encrypted[i] ^ key[i % len(key)]) for i in range(len(encrypted)))\n"
    output_code += "    return decrypted\n\n"
    output_code += "if __name__ == \"__main__\":\n"
    output_code += f"    encrypted_code = [{encrypted_hex}]\n"
    output_code += f"    key = [{key_hex}]\n"
    output_code += f"    decrypted_code = {decrypt_func}(encrypted_code, key)\n"
    output_code += "    exec(decrypted_code)\n"
    return output_code


def encrypt(original_code, iterations):
    crypted_code = original_code
    print("Expected iterations: "+str(iterations)+"\n")
    for i in range(iterations):
        type = random.randint(1,4)
        if type == 1:
            crypted_code = encryption_metode_1(crypted_code)
            print("Encrypted with metode 1")
        else:
            if type == 2:
                crypted_code = encryption_metode_2(crypted_code)
                print("Encrypted with metode 2")
            else:
                if type == 3:
                    crypted_code = encryption_metode_3(crypted_code)
                    print("Encrypted with metode 3")
                else:
                    if type == 4:
                        crypted_code = encryption_metode_4(crypted_code)
                        print("Encrypted with metode 4")
    return crypted_code




if __name__ == "__main__":
    #Preparing for encription
    file_py = sys.argv[1]
    libraris = get_libraris(file_py)
    original_code = code_without_libraries(file_py)
    
    #Encripting:
    crypted_code = encrypt(original_code, iterations)
    
    #Creating output file
    save_output_into_file(os.path.basename(sys.argv[1]), crypted_code, libraris)
    
