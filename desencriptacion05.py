import getpass
import struct
import sys

from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def validar_umbral(texto):
    try:
        umbral = int(str(texto).strip())
    except ValueError:
        raise ValueError(f"El umbral debe ser un número entero entre 0 y 255 (recibí '{texto}').")
    if not 0 <= umbral <= 255:
        raise ValueError(f"El umbral debe estar entre 0 y 255 (recibí {umbral}).")
    return umbral


def pixeles_aptos(imagen, umbral):
    ancho, alto = imagen.size
    pixeles = imagen.load()
    corte = umbral >> 1
    for y in range(alto):
        for x in range(ancho):
            if (pixeles[x, y] >> 1) > corte:
                yield x, y


def bits_a_bytes(bits):
    datos = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        datos.append(byte)
    return bytes(datos)


def leer_bits(imagen, cantidad, umbral):
    pixeles = imagen.load()
    bits = []
    for x, y in pixeles_aptos(imagen, umbral):
        bits.append(pixeles[x, y] & 1)
        if len(bits) >= cantidad:
            break
    return bits


def extraer_mensaje(ruta_imagen, clave, umbral):
    imagen = Image.open(ruta_imagen).convert("L")
    capacidad = sum(1 for _ in pixeles_aptos(imagen, umbral))
    error_umbral = ValueError(
        "No se pudo leer un mensaje: el umbral es incorrecto, la imagen no tiene "
        "mensaje oculto o fue modificada."
    )

    if capacidad < 32:
        raise error_umbral
    (largo,) = struct.unpack(">I", bits_a_bytes(leer_bits(imagen, 32, umbral)))
    total_bits = 32 + largo * 8
    if largo < 12 + 16 or total_bits > capacidad: 
        raise error_umbral

    paquete = bits_a_bytes(leer_bits(imagen, total_bits, umbral))[4:]
    nonce, cifrado = paquete[:12], paquete[12:]
    try:
        return AESGCM(clave).decrypt(nonce, cifrado, None).decode("utf-8")
    except InvalidTag:
        raise ValueError(
            "No se pudo descifrar: la contraseña o el umbral son incorrectos, "
            "o la imagen fue modificada."
        )

def limpiar_ruta(ruta):
    return ruta.strip().strip('"').strip("'")


def convertir_contrasena(texto):
    try:
        clave = bytes.fromhex(texto.strip())
    except ValueError:
        raise ValueError("La contraseña debe ser texto hexadecimal (solo 0-9 y a-f).")
    if len(clave) != 32:
        raise ValueError(
            f"La contraseña debe tener 64 caracteres hexadecimales (tiene {len(texto.strip())})."
        )
    return clave


def pedir_datos():
    args = sys.argv[1:]
    if len(args) >= 3:  # ruta (puede tener espacios), contraseña, umbral de Otsu
        return limpiar_ruta(" ".join(args[:-2])), args[-2], args[-1]
    ruta = limpiar_ruta(" ".join(args)) if args else limpiar_ruta(input("Ruta de la imagen encriptada: "))
    contrasena = getpass.getpass("Contraseña (no se muestra al escribir): ")
    umbral = input("Umbral de Otsu utilizado durante la encriptación: ")
    return ruta, contrasena, umbral


def principal():
    try:
        ruta, contrasena, umbral = pedir_datos()
        mensaje = extraer_mensaje(ruta, convertir_contrasena(contrasena), validar_umbral(umbral))
    except (OSError, ValueError) as error:
        sys.exit(f"Error: {error}")
    print(f"Mensaje descifrado: ({mensaje})")


if __name__ == "__main__":
    principal()
