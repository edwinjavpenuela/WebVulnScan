import subprocess

def ejecutar_nmap(url, tipo_escaneo):
    if tipo_escaneo == "sigiloso":
        # Comando de escaneo sigiloso
        comando = ["nmap", "-sS", "-T2", "-p-", url]  # -sS para escaneo TCP SYN, -T2 para un escaneo lento
    elif tipo_escaneo == "agresivo":
        # Comando de escaneo agresivo
        comando = ["nmap", "-A", "-T4", "-p-", url]  # -A para escaneo agresivo, -T4 para mayor velocidad
    else:
        print("Tipo de escaneo no válido")
        return

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
        print(resultado.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar nmap: {e.stderr}")

def main():
    url = input("Introduce la URL o dirección IP de la aplicación web: ")
    print("Selecciona el tipo de escaneo:")
    print("1. Escaneo sigiloso")
    print("2. Escaneo agresivo")
    
    opcion = input("Introduce el número de la opción deseada: ")
    
    if opcion == "1":
        ejecutar_nmap(url, "sigiloso")
    elif opcion == "2":
        ejecutar_nmap(url, "agresivo")
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
