import hashlib

def crack_sha1_hash(hash_to_crack, use_salts=False):
    # 1. Leer las 10,000 contraseñas más comunes
    passwords = []
    try:
        with open("top-10000-passwords.txt", "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return "Error: top-10000-passwords.txt not found"

    # 2. Si use_salts es True, cargar la lista de sales conocidas
    salts = []
    if use_salts:
        try:
            with open("known-salts.txt", "r", encoding="utf-8") as f:
                salts = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return "Error: known-salts.txt not found"

    # 3. Procesar y comparar contraseñas
    for password in passwords:
        if use_salts:
            # El requerimiento dice: append AND prepend (añadir antes Y después)
            # Debemos probar cada sal de forma independiente, poniéndola antes y poniéndola después
            for salt in salts:
                # Caso A: Salt al principio (prepend)
                prepended = f"{salt}{password}".encode('utf-8')
                if hashlib.sha1(prepended).hexdigest() == hash_to_crack:
                    return password
                
                # Caso B: Salt al final (append)
                appended = f"{password}{salt}".encode('utf-8')
                if hashlib.sha1(appended).hexdigest() == hash_to_crack:
                    return password
        else:
            # Caso Estándar: Sin sales, hash directo de la contraseña
            encoded_password = password.encode('utf-8')
            if hashlib.sha1(encoded_password).hexdigest() == hash_to_crack:
                return password

    # 4. Si recorrió todo el diccionario y no hubo match
    return "PASSWORD NOT IN DATABASE"