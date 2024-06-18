"""
Consideraciones antes de ejecutar
Requisitos:
- El programa esta hecho para uso exclusivo de Linux
- Se requiere que se generen las llaves (publica y privada)
  en el equipo donde se desea enviar los mensajes
- Contar con las rutas completas de las llaves del otro equipo
- Se debe contar con un usuario y contraseña en el otro equipo
  para hacer uso del SSH 
- En el equipo donde llegaran los mensajes se debe contar con
  el servicio SSH activo al momento de la comunicacion

Para generar las llaves se pueden usar los comandos:
1. openssl genpkey -algorithm RSA -out private_key.pem -aes256
2. openssl rsa -pubout -in private_key.pem -out public_key.pem
Para asegurarnos que la llave privada no tiene contraseña ya que
   esto provoca un error a la hora de la ejecucion del programa)
3. openssl rsa -in private_key.pem -out private_key.pem
"""

from datetime import datetime
import getpass
import hashlib
import os
import platform
import re
import subprocess
import tempfile
import paramiko # type: ignore

# Declarar las variables globales
username = None
password = None
port = 22
ip_req = None

# Funcion para solicitar la ip a donde nos vamos a conectar
def solicitar_ip():
    global ip_req
    while True:
        # Solicita la ip
        ip_req = input("Ingrese la direccion IP: ")
        #ip_req = '192.168.1.127'

        # Validar la entrada de la ip usando expresiones regulares
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_req):
            return ip_req
        else:
            print("La dirección IP ingresada no es válida. Intente nuevamente.")

# Funcion para obtener la MAC ADDRESS de la maquina
def obtener_mac_address(ip_address):
    command = f"arp -a {ip_address}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    pattern = r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
    match = re.search(pattern, output.decode('utf-8'))
    if match:
        return match.group(1)
    else:
        return None
    
# Funcion para capturar el log
def registrar_log(ip_address, mac_address):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{current_time} - {ip_address} - {mac_address}\n"

    # Checar si existe el archivo para log
    if not os.path.exists("connection.log"):
        # Si no existe crearlo
        with open("connection.log", "w") as log_file:
            pass  # Crea arhivo en blanco

    # Agregar log al archivo
    with open("connection.log", "a") as log_file:
        log_file.write(log_entry)

# Funcion para obtener la llave publica
def get_public_key(ip_address, route):
    global username, password, port
    print("---------------------------------------")
    print("DATOS CONEXION SSH")
    username = input("Ingrese su nombre de usuario: ")
    #username = 'rafaelpj'
    password = getpass.getpass(prompt="Ingrese la contraseña del usuario remoto: ")  # Secure password input
    #password = '123456'
    if input("Su puerto es el predeterminado? (y/n): ") == 'y':
        port = 22
    else:
        port = input("Ingrese su puerto: ")
    #port = 22
    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para la transferencia de archivos
        sftp = client.open_sftp()

        # Definir la rutas de la fuente y el destino
        local_path = input("Ingrese la ruta (completa solo carpetas) donde desea guardar la llave publica:")
        local_path = f"{local_path}/public_key.pem"
        #local_path = '/home/rafaelpj/compartida/Equipo2/public_key.pem'
        remote_path = f"{route}"

        # Transferencia del archivo usando SCP
        sftp.put(remote_path, local_path)

        # Cerrar las conecciones
        sftp.close()
        client.close()

        print("La llave publica se ha obtenido con éxito")
    
    except paramiko.SSHException as e:
        print(f"Error al transferir la llave: {e}")
    except FileNotFoundError:
        print(f"No se encontró el archivo en la ruta remota: {remote_path}")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Funcion para mandar mensajes
def send_message(route):
    msg = input("Ingresa tu mensaje: ")
    # Crear un archivo temporal
    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', encoding='utf-8')
    temp_file.write(msg)

    # Obtener la ruta del archivo temporal
    temp_file_path = temp_file.name

    temp_file.close()

    send_file(temp_file_path, route)

    try:
        os.remove(temp_file_path)
        #print(f"Archivo temporal {temp_file_path} eliminado con éxito.")
    except Exception as e:
        print(f"Error al eliminar el archivo temporal: {e}")

# Funcion para mandar archivos
def send_file(file_path, route): 
    global ip_req
    global username, password, port
    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para la transferencia de archivos
        sftp = client.open_sftp()

        # Definir la rutas de la fuente y el destino
        modify_route = os.path.dirname(route)
        file_name = os.path.basename(file_path)
        file_name = os.path.splitext(file_name)[0]
        base_path = f"{modify_route}/"

        # Definir listas de rutas vacias
        rutas_no_y = []
        rutas_y = []

        sha384_path = get_hash_sha384(file_path)
        
        encrypted_path = encrypt(file_path, route)

        sha512_path = get_hash_sha512(encrypted_path)

        opcion = input("Deseas esconder el archivo encriptado? (y/n): ")

        if opcion == 'y':

            steg_path = steg_file(encrypted_path)

            blake2_path = get_hash_blake2(steg_path)


        # Transferencia del archivo usando SCP (HASH sha384)
        sftp.put(sha384_path, f"{base_path}{os.path.basename(sha384_path)}")
        rutas_no_y.append(f"{base_path}{os.path.basename(sha384_path)}")
        rutas_y.append(f"{base_path}{os.path.basename(sha384_path)}")

        # Transferencia del archivo usando SCP (HASH sha512)
        sftp.put(sha512_path, f"{base_path}{os.path.basename(sha512_path)}")
        rutas_no_y.append(f"{base_path}{os.path.basename(sha512_path)}")
        rutas_y.append(f"{base_path}{os.path.basename(sha512_path)}")

        if opcion != 'y':
            # Transferencia del archivo usando SCP (Archivo Encriptado)
            sftp.put(encrypted_path, f"{base_path}{os.path.basename(encrypted_path)}")
            rutas_no_y.append(f"{base_path}{os.path.basename(encrypted_path)}")

            # Eliminar el archivo encriptado después de enviarlo
            os.remove(encrypted_path)
            print(f"Archivo encriptado {encrypted_path} eliminado correctamente.")

            # Orden de la lista de rutas
            # [sha384, sha512, encrypt]
            verify_integrity(ip_req, 'e', rutas_no_y)

        if opcion == 'y':
            # Transferencia del archivo usando SCP (stegobjeto)
            sftp.put(steg_path, f"{base_path}{os.path.basename(steg_path)}")
            rutas_y.append(f"{base_path}{os.path.basename(steg_path)}")

            # Transferencia del archivo usando SCP (HASH blake2)
            sftp.put(blake2_path, f"{base_path}{os.path.basename(blake2_path)}")
            rutas_y.append(f"{base_path}{os.path.basename(blake2_path)}")

            # Eliminar el archivo esteganografiado después de enviarlo
            os.remove(steg_path)
            print(f"Archivo esteganografiado {steg_path} eliminado correctamente.")

            # Orden de la lista de rutas
            # [sha384, sha512, stegobjeto, blake2]
            verify_integrity(ip_req, 's', rutas_y)

        # Cerrar las conecciones
        sftp.close()
        client.close()

    except paramiko.SSHException as e:
        print(f"Error al transferir el paquete: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Funcion para obtener el hash 384
def get_hash_sha384(file_path):
    try:
        # Crear un objeto hash SHA-384
        sha384_hash = hashlib.sha384()

        # Leer el archivo en bloques
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha384_hash.update(block)

        # Obtener el hash en formato hexadecimal
        hash_hex = sha384_hash.hexdigest()

        # Definir la ruta y el nombre del archivo de hash
        hash_file_path = f"{file_path}.sha384"

         # Escribir el hash en el archivo
        with open(hash_file_path, 'w') as hash_file:
            hash_file.write(hash_hex)

        #print(f"Hash SHA-384 calculado y guardado en {hash_file_path}")

        # Retornar la ruta del archivo de hash
        return hash_file_path

    except Exception as e:
        print(f"Error al calcular o guardar el hash: {e}")

# Funcion para obtener hash 512
def get_hash_sha512(file_path):
    try:
        # Crear un objeto hash SHA-512
        sha512_hash = hashlib.sha512()

        # Leer el archivo en bloques y actualizar el hash
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha512_hash.update(block)

        # Obtener el hash en formato hexadecimal
        hash_hex = sha512_hash.hexdigest()

        # Definir la ruta y el nombre del archivo de hash
        hash_file_path = f"{file_path}.sha512"

        # Escribir el hash en el archivo
        with open(hash_file_path, 'w') as hash_file:
            hash_file.write(hash_hex)

        #print(f"Hash SHA-512 calculado y guardado en {hash_file_path}")

        # Retornar la ruta del archivo de hash
        return hash_file_path

    except Exception as e:
        print(f"Error al calcular o guardar el hash: {e}")
        return None

# Función para encriptar con la llave pública obtenida usando OpenSSL rsautl
def encrypt(file_path, route):
    try:
        # Comando para encriptar usando OpenSSL rsautl
        command_encrypt_key = f"openssl pkeyutl -encrypt -pubin -inkey {route} -in {file_path} -out {file_path}.enc"

        # Ejecutar el comando
        subprocess.run(command_encrypt_key, shell=True, check=True)

        print(f"Archivo encriptado")
        return f"{file_path}.enc"

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando OpenSSL: {e}")
        return None
    except Exception as e:
        print(f"Error inesperado al encriptar el archivo: {e}")
        return None

def get_file_size(file_path):
    if platform.system() == "Windows":
        result = subprocess.run(['powershell', '-command', f"(Get-Item '{file_path}').length"], capture_output=True, text=True, check=True)
    else:
        result = subprocess.run(['stat', '-c%s', file_path], capture_output=True, text=True, check=True)
        print(f"TAMAÑO: {result.stdout.strip()}")
    return result.stdout.strip()

def concat_files(file1, file2, output_file):
    if platform.system() == "Windows":
        command = f"type {file1} {file2} > {output_file}"
    else:
        command = f"cat {file1} {file2} > {output_file}"
    subprocess.run(command, shell=True, check=True)

# Función para ocultar el archivo encriptado dentro de otro usando cat
def steg_file(file_path):
    try:
        # Obtener la ruta del archivo destino para ocultar (steganography)
        steg_file_path = input("Ingresa la ruta completa donde quieres ocultar el archivo encriptado: ")

        # Verificar si ambos archivos existen
        if not os.path.exists(file_path):
            print(f"El archivo {file_path} no existe.")
            return None
        
        if not os.path.exists(steg_file_path):
            print(f"El archivo destino {steg_file_path} no existe.")
            return None
        
        # Obtener el tamaño del archivo original
        original_file_size = get_file_size(file_path)

        # Nombre del archivo esteganografiado con el tamaño del archivo original
        stegged_file_path = f"{steg_file_path}.steg.{original_file_size}"

        # Concatenar el archivo destino con el archivo encriptado
        concat_files(steg_file_path, file_path, stegged_file_path)

        print("Stegobjeto generado correctamente.")

        # Eliminar el archivo encriptado original
        os.remove(file_path)
        print(f"Stegobjeto {file_path} eliminado correctamente.")
        
        # Devolver la ruta del archivo esteganografiado
        return stegged_file_path

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando de concatenación: {e}")
        return None
    except Exception as e:
        print(f"Error inesperado al ocultar el archivo encriptado: {e}")
        return None
    
# Función para obtener hash Blake2
def get_hash_blake2(file_path):
    try:
        # Tamaño de salida deseado en bytes (en este caso, 64 bytes para Blake2b)
        hash_size = 64

        # Crear un objeto hash Blake2b
        hash_blake2 = hashlib.blake2b(digest_size=hash_size)

        # Leer el archivo en bloques y actualizar el hash
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                hash_blake2.update(block)

        # Obtener el hash en formato hexadecimal
        hash_hex = hash_blake2.hexdigest()

        # Definir la ruta y el nombre del archivo de hash
        hash_file_path = f"{file_path}.blake2"

        # Escribir el hash en el archivo
        with open(hash_file_path, 'w') as hash_file:
            hash_file.write(hash_hex)

        print(f"Hash Blake2 calculado y guardado en {hash_file_path}")

        # Retornar la ruta del archivo de hash
        return hash_file_path

    except Exception as e:
        print(f"Error al calcular o guardar el hash Blake2: {e}")
        return None

def verify_integrity(ip_address, mode, path_list):
    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para el manejo de archivos
        sftp = client.open_sftp()

        if mode == 's':
            # [sha384, sha512, stegobjeto, blake2]
            print("Verificando stegobjeto")
            steg_path = path_list[2] # Por el orden de la lista
            blake2_hash_gen = generate_blake2_hash(steg_path, ip_address)
            #print(f"Hash BLAKE2 generado del stegobjeto: {blake2_hash_gen}")
            
            # Leer el hash BLAKE2 del archivo de forma remota
            blake2_path = path_list[3]  
            with sftp.open(blake2_path, 'rb') as f:
                blake2_hash_remote = f.read().decode()

            #print(f"Hash BLAKE2 enviado: {blake2_hash_remote}")

            # Comparar los hashes BLAKE2
            if blake2_hash_gen == blake2_hash_remote:
                print("Hash BLAKE2 Verificado")
                try:
                    sftp.remove(blake2_path)
                    #print(f"Archivo remoto {blake2_path} eliminado")
                except Exception as e:
                    print(f"Error al eliminar el archivo remoto {file_path}: {e}")

                # Aplicar split text para sacar el objeto del setgobjeto
                print("Sacando archivo encriptado...")
                enc_path = split(steg_path, ip_address)
                sha512_path = path_list[1]
                sha384_path = path_list[0]
                
                # No pude
                print("No se pudo...")
                return

            else:
                print("Hash BLAKE2 fallo, comunicacion alterada")
                print("Borrando informacion...")
                for file_path in path_list:
                    try:
                        sftp.remove(file_path)
                        print(f"Archivo remoto {file_path} eliminado")
                    except Exception as e:
                        print(f"Error al eliminar el archivo remoto {file_path}: {e}")
                
                # Cerrar las conecciones
                sftp.close()
                client.close()
                return

                    
        # [sha384, sha512, encrypt]
        if mode != 's':
            enc_path = path_list[2]
            sha512_path = path_list[1]
            sha384_path = path_list[0]

        # Generar sha512
        print("Verificando archivo encriptado")
        sha512_hash_gen = generate_sha512_hash(enc_path, ip_address)
        #print(f"Hash SHA512 generado del encriptado: {sha512_hash_gen}")

        # Leer el hash sha512 del archivo de forma remota  
        with sftp.open(sha512_path, 'rb') as f:
            sha512_hash_remote = f.read().decode()

        #print(f"Hash SHA512 enviado: {sha512_hash_remote}")

        # Comparar los hashes sha512
        if sha512_hash_gen == sha512_hash_remote:
            print("Hash SHA512 Verificado")
            try:
                sftp.remove(sha512_path)
                #print(f"Archivo remoto {sha512_path} eliminado")
            except Exception as e:
                print(f"Error al eliminar el archivo remoto {sha512_path}: {e}")

            # Desencriptar archivo
            original_path = decrypt(enc_path, ip_address)
            
            # Generar sha384
            print("Verificando archivo desencriptado")
            sha384_hash_gen = generate_sha384_hash(original_path, ip_address)
            #print(f"Hash SHA384 generado del archivo: {sha384_hash_gen}")

            try:
                sftp.remove(enc_path)
                #print(f"Archivo remoto {enc_path} eliminado")
            except Exception as e:
                print(f"Error al eliminar el archivo remoto {enc_path}: {e}")


            # Leer el hash sha384 del archivo de forma remota  
            with sftp.open(sha384_path, 'rb') as f:
                sha384_hash_remote = f.read().decode()

            #print(f"Hash SHA384 enviado: {sha384_hash_remote}")

            # Comparar los hashes sha384
            if sha384_hash_gen == sha384_hash_remote:
                print("Hash SHA384 Verificado")
                try:
                    sftp.remove(sha384_path)
                    #print(f"Archivo remoto {sha384_path} eliminado")
                except Exception as e:
                    print(f"Error al eliminar el archivo remoto {sha384_path}: {e}")

                # Confirmacion
                print("---------------------------------------")
                print("MENSAJE LISTO. NO SUFRIO MODIFICACIONES")

            else:
                    print("Hash SHA384 fallo, comunicacion alterada")
                    print("Borrando informacion...")
                    for file_path in path_list:
                        try:
                            sftp.remove(file_path)
                            print(f"Archivo remoto {file_path} eliminado")
                        except Exception as e:
                            print(f"Error al eliminar el archivo remoto {file_path}: {e}")
                    # Cerrar las conecciones
                    sftp.close()
                    client.close()
                    return

        else:
            print("Hash SHA512 fallo, comunicacion alterada")
            print("Borrando informacion...")
            for file_path in path_list:
                try:
                    sftp.remove(file_path)
                    print(f"Archivo remoto {file_path} eliminado")
                except Exception as e:
                    print(f"Error al eliminar el archivo remoto {file_path}: {e}")
            
            # Cerrar las conecciones
            sftp.close()
            client.close()
            return
            
        # Cerrar las conecciones
        sftp.close()
        client.close()
    
    except paramiko.SSHException as e:
        print(f"Error en la conexion SSH: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Genera hash blake2
def generate_blake2_hash(steg_path, ip_address):
    global ip_req
    global username, password, port

    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para el manejo de archivos
        sftp = client.open_sftp()

        try:
            # Tamaño de salida deseado en bytes (en este caso, 64 bytes para Blake2b)
            hash_size = 64

            # Crear un objeto hash Blake2b
            hash_blake2 = hashlib.blake2b(digest_size=hash_size)

            # Leer el archivo en bloques y actualizar el hash
            with sftp.open(steg_path, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    hash_blake2.update(block)

            # Obtener el hash en formato hexadecimal
            hash_hex = hash_blake2.hexdigest()

            sftp.close()
            client.close()
            return hash_hex

        except Exception as e:
            print(f"Error al calcular el hash Blake2: {e}")
            return None

    except paramiko.SSHException as e:
        print(f"Error en la conexion SSH: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

# Función para obtener el tamaño del archivo desde el nombre del archivo esteganografiado
def get_steg_file_size(steg_path):
    steg_filename, steg_extension = os.path.splitext(os.path.basename(steg_path))

    # Extract the last numeric component from the filename
    # (assuming the format is "<name>.<size>.steg")
    size_str = steg_filename.split('.')[-1]
    try:
        steg_file_size = int(size_str)
    except ValueError:
        print(f"Error getting file size from filename: {steg_filename}. Using default size.")
        steg_file_size = 1024 * 1024  # Default size is 1 MB

    return steg_file_size

# Aplicar split para sacar el archivo encriptado
def split(steg_path, ip_address):
    steg_file_size = get_steg_file_size(steg_path)
    output_prefix = 'Escondido'
    original_file_path = None

    try:
        # Create an SSH client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Create an SSH transport for executing commands
        transport = client.get_transport()

        # Execute the `split` command
        split_command = f"split -b {steg_file_size} {steg_path} {output_prefix}_"
        channel = transport.open_session()
        channel.exec_command(split_command)
        channel.close()

        # Reconstruct the original file on the remote server (optional)
        original_file_path = f"{os.path.dirname(steg_path)}/{output_prefix}"
        reconstruct_command = f"cat {output_prefix}_* > {original_file_path}"
        channel = transport.open_session()
        channel.exec_command(reconstruct_command)

        # Handle the output and errors of the reconstruction command
        if channel.recv_exit_status() != 0:
            error_message = channel.recv_stderr().decode().strip()
            print(f"Error al reconstruir archivo: {error_message}")
            original_file_path = None
        else:
            print("Archivo reconstruido exitosamente")

        # Close the channels and transport
        channel.close()
        transport.close()

    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        # Ensure transport is closed even if exceptions occur
        if transport:
            transport.close()

    # Close the client connection at the end
    client.close()

    return original_file_path

def natural_sorting(x):
    if isinstance(x, bytes):
        return re.sub(r'[^0-9]', '', x)
    return [int(i) if i.isdigit() else i for i in re.sub(r'\s+', ' ', x).split(' ')]

def sorted(iterable, key=natural_sorting):
    return sorted(iterable, key=key)

def generate_sha512_hash(enc_path, ip_address):
    global ip_req
    global username, password, port

    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para el manejo de archivos
        sftp = client.open_sftp()

        try:
            # Crear un objeto hash SHA-512
            sha512_hash = hashlib.sha512()

            # Leer el archivo en bloques y actualizar el hash
            with sftp.open(enc_path, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    sha512_hash.update(block)

            # Obtener el hash en formato hexadecimal
            hash_hex = sha512_hash.hexdigest()

            sftp.close()
            client.close()
            return hash_hex

        except Exception as e:
            print(f"Error al calcular el hash SHA512: {e}")
            return None

    except paramiko.SSHException as e:
        print(f"Error en la conexion SSH: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

def decrypt(enc_path, ip_address):
    global username, password, port

    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un SSH transport para ejecutar comandos
        transport = client.get_transport()

        # Ruta temporal en el servidor para el archivo desencriptado
        remote_decrypted_file_path = f"{os.path.dirname(enc_path)}/original"

        #private_key_path = input("Ingresa la ruta de la llave privada: ")
        private_key_path = '/home/rafaelpj/compartida/Equipo1/private_key.pem'

        try:
            # Comando para desencriptar usando OpenSSL rsautl
            command_decrypt = f"openssl pkeyutl -decrypt -inkey {private_key_path} -in {enc_path} -out {remote_decrypted_file_path}"
            channel = transport.open_session()
            channel.exec_command(command_decrypt)

            if channel.recv_exit_status() != 0:
                error_message = channel.recv_stderr().decode().strip()
                print(f"Error al desencriptar el archivo: {error_message}")
                return None
            #else:
                #print(f"Archivo desencriptado correctamente y guardado en: {remote_decrypted_file_path}")

        finally:
            # Cerrar las conexiones
            channel.close()
            client.close()
            return remote_decrypted_file_path 
             
    except paramiko.SSHException as e:
        print(f"Error en la conexión SSH: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

def generate_sha384_hash(original_path, ip_address):
    global ip_req
    global username, password, port

    try:
        # Crear un cliente SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip_address, port, username, password)

        # Crear un cliente SFTP para el manejo de archivos
        sftp = client.open_sftp()

        try:
            # Crear un objeto hash SHA-384
            sha384_hash = hashlib.sha384()

            # Leer el archivo en bloques
            with open(original_path, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    sha384_hash.update(block)

            # Obtener el hash en formato hexadecimal
            hash_hex = sha384_hash.hexdigest()

            sftp.close()
            client.close()
            return hash_hex

        except Exception as e:
            print(f"Error al calcular el hash SHA384: {e}")
            return None

    except paramiko.SSHException as e:
        print(f"Error en la conexion SSH: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")    

# Ciclo principal
if __name__ == "__main__":

    ip_address = solicitar_ip()
    mac_address = obtener_mac_address(ip_address)

    if mac_address:
        print(f"La dirección MAC asociada a la IP {ip_address} es: {mac_address}")
        registrar_log(ip_address, mac_address)

        # Pedir la ruta de la llave publica
        route = input("Ingrese la ruta de la llave publica: ")
        #route = '/home/rafaelpj/compartida/Equipo1/public_key.pem'
        get_public_key(ip_address, route)

        # Cliclo para enviar
        while True:
            print("---------------------------------------")
            opcion = input("¿Desea enviar un mensaje (m), archivo (f) o salir (s)? ").strip().lower()

            if opcion == 'm':
                send_message(route)

            elif opcion == 'f':
                file_path = input("Ingresa la ruta (completa) del archivo: ")
                send_file(file_path, route)

            elif opcion == 's':
                print("Saliendo...")

                break
            else:
                print("Opción no válida. Intente nuevamente.")

    else:
        print(f"No se pudo encontrar la dirección MAC para la IP {ip_address}")