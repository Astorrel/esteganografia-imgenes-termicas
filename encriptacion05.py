import os
import struct
import sys

import numpy as np
from PIL import Image
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from skimage.filters import threshold_otsu
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

NOMBRE_ARCHIVO_MENSAJE = "mensaje.txt"

def validar_umbral(texto):
    try:
        umbral = int(str(texto).strip())
    except ValueError:
        raise ValueError(f"El umbral debe ser un número entero entre 0 y 255 (recibí '{texto}').")
    if not 0 <= umbral <= 255:
        raise ValueError(f"El umbral debe estar entre 0 y 255 (recibí {umbral}).")
    return umbral


def calcular_umbral_otsu(imagen):
    """Calcula el umbral de Otsu sobre la imagen original (escala de grises)."""
    return validar_umbral(int(threshold_otsu(np.array(imagen))))


def calcular_metricas(original, resultado):
    """Devuelve (PSNR en dB, SSIM) entre la imagen original y la modificada."""
    a = np.array(original)
    b = np.array(resultado)
    psnr = peak_signal_noise_ratio(a, b, data_range=255)
    ssim = structural_similarity(a, b, data_range=255)
    return psnr, ssim


def gris_minimo(umbral): 
    return 2 * ((umbral >> 1) + 1)


def pixeles_aptos(imagen, umbral):
    ancho, alto = imagen.size
    pixeles = imagen.load()
    corte = umbral >> 1
    for y in range(alto):
        for x in range(ancho):
            if (pixeles[x, y] >> 1) > corte:
                yield x, y


def bytes_a_bits(datos):
    bits = []
    for byte in datos:
        for posicion in range(7, -1, -1):
            bits.append((byte >> posicion) & 1)
    return bits


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
    if cantidad == 0:
        return bits
    for x, y in pixeles_aptos(imagen, umbral):
        bits.append(pixeles[x, y] & 1)
        if len(bits) >= cantidad:
            break
    return bits

def ocultar_mensaje(imagen, mensaje, clave, umbral):
    nonce = os.urandom(12)
    cifrado = AESGCM(clave).encrypt(nonce, mensaje.encode("utf-8"), None)

    paquete = nonce + cifrado
    datos = struct.pack(">I", len(paquete)) + paquete  
    bits = bytes_a_bits(datos)

    capacidad = sum(1 for _ in pixeles_aptos(imagen, umbral))
    if len(bits) > capacidad:
        raise ValueError(
            f"El mensaje necesita {len(bits)} píxeles y con umbral {umbral} la imagen solo "
            f"tiene {capacidad} aptos (gris >= {gris_minimo(umbral)}). "
        )

    resultado = imagen.copy()
    pixeles = resultado.load()
    for bit, (x, y) in zip(bits, pixeles_aptos(imagen, umbral)):
        pixeles[x, y] = (pixeles[x, y] & 0xFE) | bit
    return resultado


def extraer_mensaje(ruta_imagen, clave, umbral):
    imagen = Image.open(ruta_imagen).convert("L")
    capacidad = sum(1 for _ in pixeles_aptos(imagen, umbral))
    error_umbral = ValueError(
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


def pedir_ruta():
    args = sys.argv[1:]
    if args:
        return limpiar_ruta(" ".join(args))
    return limpiar_ruta(input("Ruta de la imagen: "))


def ruta_de_salida(ruta_imagen):
    carpeta, archivo = os.path.split(ruta_imagen)
    nombre, _ = os.path.splitext(archivo)
    return os.path.join(carpeta, nombre + "_encriptado.png")


def leer_mensaje(carpeta):
    ruta = os.path.join(carpeta, NOMBRE_ARCHIVO_MENSAJE)
    if not os.path.isfile(ruta):
        raise FileNotFoundError(
            f"No encontré '{NOMBRE_ARCHIVO_MENSAJE}' en {carpeta or 'la carpeta actual'}. "
            "Crea ese archivo con el texto a ocultar, junto a la imagen."
        )
    with open(ruta, "r", encoding="utf-8") as archivo:
        texto = archivo.read().strip()
    if not texto:
        raise ValueError(f"'{ruta}' está vacío: no hay nada que ocultar.")
    return texto

def mostrar_ventana(ruta_original, ruta_encriptada, mensaje, ancho_max=480, alto_max=480):
    try:
        import tkinter as tk
        from PIL import ImageTk
    except ImportError:
        print("tkinter no está disponible; abro las imágenes con el visor del sistema.")
        Image.open(ruta_original).show()
        Image.open(ruta_encriptada).show()
        return

    ventana = tk.Tk()
    ventana.title("")  

    fotos = []  

    def preparar(ruta):
        img = Image.open(ruta).convert("L")
        factor = min(ancho_max / img.size[0], alto_max / img.size[1])
        nuevo = (max(1, round(img.size[0] * factor)), max(1, round(img.size[1] * factor)))
        metodo = Image.NEAREST if factor >= 1 else Image.LANCZOS
        foto = ImageTk.PhotoImage(img.resize(nuevo, metodo))
        fotos.append(foto)
        return foto

    marco = tk.Frame(ventana, padx=12, pady=12)
    marco.pack()
    for columna, ruta in enumerate([ruta_original, ruta_encriptada]):
        tk.Label(marco, image=preparar(ruta)).grid(row=0, column=columna, padx=8)

    tk.Label(ventana, text=f"({mensaje})", font=("Arial", 12),
             wraplength=2 * ancho_max, pady=10).pack()

    ventana.mainloop()

def principal():
    try:
        ruta_imagen = pedir_ruta()
        if not os.path.isfile(ruta_imagen):
            raise FileNotFoundError(f"No existe el archivo: {ruta_imagen}")

        carpeta = os.path.dirname(os.path.abspath(ruta_imagen))
        mensaje = leer_mensaje(carpeta)
        imagen = Image.open(ruta_imagen).convert("L")  
        umbral = calcular_umbral_otsu(imagen)
        clave = os.urandom(32)
        resultado = ocultar_mensaje(imagen, mensaje, clave, umbral)
    except (OSError, ValueError) as error:
        sys.exit(f"Error: {error}")

    salida = ruta_de_salida(os.path.abspath(ruta_imagen))
    resultado.save(salida, format="PNG")
    aptos = sum(1 for _ in pixeles_aptos(imagen, umbral))
    psnr, ssim = calcular_metricas(imagen, resultado)
    print(f"Imagen guardada en: {salida}")
    print(f"Umbral de Otsu calculado y utilizado: {umbral}")
    print(f"Píxeles usados: los de gris >= {gris_minimo(umbral)} "
          f"({aptos} de {imagen.size[0] * imagen.size[1]} disponibles)")
    print(f"PSNR: {psnr:.4f} dB")
    print(f"SSIM: {ssim:.6f}")
    print(f"Contraseña (guárdala junto con el umbral {umbral}): {clave.hex()}")

    recuperado = extraer_mensaje(salida, clave, umbral)
    mostrar_ventana(ruta_imagen, salida, recuperado)


if __name__ == "__main__":
    principal()
