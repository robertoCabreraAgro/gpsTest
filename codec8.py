import socket
import json
import os
import datetime
import struct
import decimal
#import psycopg2
#from pyproj import Transformer
import threading  # Importamos threading para manejar múltiples hilos

HOST = '0.0.0.0'  # Puede que '0.0.0.0' no funcione en algunos sistemas Linux; cambia a una cadena con la dirección IP, por ejemplo: '192.168.0.1'
PORT = 5055  # Cambia esto por el puerto que estás utilizando



def insertar_datos_gps(io_dict):
    print("SimulDatos que se insertarían en la BD:", io_dict)

   
def input_trigger():  # Espera la entrada del usuario
    print("Escribe 'SERVER' para iniciar el servidor o:")
    print("Escribe 'EXIT' para detener el programa")
    device_imei = "default_IMEI"
    user_input = input("Esperando entrada: ")
    if user_input.upper() == "EXIT":
        print(f"Saliendo del programa...")
        exit()

    elif user_input.upper() == "SERVER":
        start_server_trigger()
    else:
        print("Entrada no reconocida. Intenta de nuevo.")
        input_trigger()

####################################################
###############__CRC16/ARC Checker__################
####################################################

def crc16_arc(data):
    data_part_length_crc = int(data[8:16], 16)
    data_part_for_crc = bytes.fromhex(data[16:16+2*data_part_length_crc])
    crc16_arc_from_record = data[16+len(data_part_for_crc.hex()):24+len(data_part_for_crc.hex())]

    crc = 0

    for byte in data_part_for_crc:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    if crc16_arc_from_record.upper() == crc.to_bytes(4, byteorder='big').hex().upper():
        print("CRC check passed!")
        print(f"Record length: {len(data)} characters // {int(len(data)/2)} bytes")
        return True
    else:
        print("CRC check Failed!")
        return False

####################################################

def codec_8e_checker(codec8_packet):
    if str(codec8_packet[16:16+2]).upper() != "8E" and str(codec8_packet[16:16+2]).upper() != "08":
        print()
        print(f"Invalid packet!")
        return False
    else:
        return crc16_arc(codec8_packet)

def codec_parser_trigger(codec8_packet, device_imei, props):
    try:
        return codec_8e_parser(codec8_packet.replace(" ", ""), device_imei, props)
    except Exception as e:
        print(f"Error ocurrido: {e} ingresa un paquete Codec8 válido o escribe 'EXIT'!")
        input_trigger()

def imei_checker(hex_imei):  # Función para verificar el IMEI
    imei_length = int(hex_imei[:4], 16)
    if imei_length != len(hex_imei[4:]) / 2:
        return False
    else:
        pass

    ascii_imei = ascii_imei_converter(hex_imei)
    print(f"IMEI recibido = {ascii_imei}")
    if not ascii_imei.isnumeric() or len(ascii_imei) != 15:
        print(f"No es un IMEI válido: no es numérico o tiene longitud incorrecta!")
        return False
    else:
        return True

def ascii_imei_converter(hex_imei):
    imei_bin=bytes.fromhex(hex_imei[4:])
    print(f"IMEI imei_bin = {imei_bin}")
    imei_decode=imei_bin.decode()
    print(f"IMEI imei_decode = {imei_decode}")
    return imei_decode

def start_server_trigger():
    print("Iniciando servidor!")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"// {time_stamper()} // escuchando en el puerto: {PORT} // IP: {HOST}")
        while True:
            conn, addr = s.accept()
            conn.settimeout(60)  # Tiempo de espera de la conexión
            # Iniciar un nuevo hilo para manejar la conexión
            threading.Thread(target=handle_client_connection, args=(conn, addr)).start()

def handle_client_connection(conn, addr):
    with conn:
        print(f"// {time_stamper()} // Conectado por {addr}")
        device_imei = "default_IMEI"
        while True:
            try:
                data = conn.recv(1280)
                if not data:
                    break
                print(f"// {time_stamper()} // datos recibidos = {data.hex()}")
                if imei_checker(data.hex()) != False:
                    device_imei = ascii_imei_converter(data.hex())
                    imei_reply = (1).to_bytes(1, byteorder="big")
                    conn.sendall(imei_reply)
                    print(f"-- {time_stamper()} enviando respuesta = {imei_reply}")
                elif codec_8e_checker(data.hex().replace(" ", "")) != False:
                    record_number = codec_parser_trigger(data.hex(), device_imei, "SERVER")
                    print(f"Registros recibidos {record_number}")
                    print(f"del dispositivo IMEI = {device_imei}")
                    print()
                    record_response = (record_number).to_bytes(4, byteorder="big")
                    conn.sendall(record_response)
                    print(f"// {time_stamper()} // respuesta enviada = {record_response.hex()}")
                else:
                    print(f"// {time_stamper()} // Datos no esperados recibidos - cerrando conexión")
                    break
            except socket.timeout:
                print(f"// {time_stamper()} // Tiempo de espera agotado. Cerrando conexión con {addr}")
                break

####################################################
###############_Codec8E_parser_code_################
####################################################

def codec_8e_parser(codec_8E_packet, device_imei, props):
    print(f"codec_8E_packet = {codec_8E_packet}")
    
    io_dict_raw = {}
    io_dict_raw["device_IMEI"] = device_imei
    io_dict_raw["server_time"] = time_stamper_for_json()
    io_dict_raw["data_length"] = "Record length: " + str(int(len(codec_8E_packet))) + " characters" + " // " + str(int(len(codec_8E_packet) // 2)) + " bytes"
    io_dict_raw["_raw_data__"] = codec_8E_packet

    zero_bytes = codec_8E_packet[:8]
    print()
    print(f"zero bytes = {zero_bytes}")

    data_field_length = int(codec_8E_packet[8:8+8], 16)
    print(f"data field length = {data_field_length} bytes")
    codec_type = str(codec_8E_packet[16:16+2])
    print(f"codec type = {codec_type}")

    data_step = 4
    if codec_type == "08":
        data_step = 2
    else:
        pass

    number_of_records = int(codec_8E_packet[18:18+2], 16)
    print(f"number of records = {number_of_records}")

    avl_data_start = codec_8E_packet[20:]
    data_field_position = 0

    for record_number in range(1, number_of_records + 1):
        io_dict = {}
        io_dict["device_IMEI"] = device_imei
        io_dict["server_time"] = time_stamper_for_json()
        print()
        print(f"data from record {record_number}")
        print(f"########################################")

        timestamp = avl_data_start[data_field_position:data_field_position+16]
        io_dict["_timestamp_"] = device_time_stamper(timestamp)
        print(f"timestamp = {io_dict['_timestamp_']}")
        io_dict["_rec_delay_"] = record_delay_counter(timestamp)
        data_field_position += 16  # Timestamp es de 8 bytes (16 dígitos hex)

        priority = avl_data_start[data_field_position:data_field_position+2]
        io_dict["priority"] = int(priority, 16)
        print(f"record priority = {io_dict['priority']}")
        data_field_position += 2  # Priority es de 1 byte (2 dígitos hex)

        longitude = avl_data_start[data_field_position:data_field_position+8]
        io_dict["longitude"] = coordinate_formater(longitude)
        print(f"longitude = {io_dict['longitude']}")
        data_field_position += 8

        latitude = avl_data_start[data_field_position:data_field_position+8]
        io_dict["latitude"] = coordinate_formater(latitude)
        print(f"latitude = {io_dict['latitude']}")
        data_field_position += 8

        altitude = avl_data_start[data_field_position:data_field_position+4]
        io_dict["altitude"] = int(altitude, 16)
        print(f"altitude = {io_dict['altitude']}")
        data_field_position += 4

        angle = avl_data_start[data_field_position:data_field_position+4]
        io_dict["angle"] = int(angle, 16)
        print(f"angle = {io_dict['angle']}")
        data_field_position += 4

        satelites = avl_data_start[data_field_position:data_field_position+2]
        io_dict["satelites"] = int(satelites, 16)
        print(f"satelites = {io_dict['satelites']}")
        data_field_position += 2

        speed = avl_data_start[data_field_position:data_field_position+4]
        io_dict["speed"] = int(speed, 16)
        print(f"speed = {io_dict['speed']}")
        data_field_position += 4

        event_io_id = avl_data_start[data_field_position:data_field_position+data_step]
        io_dict["eventID"] = int(event_io_id, 16)
        print(f"event ID = {io_dict['eventID']}")
        data_field_position += len(event_io_id)

        total_io_elements = avl_data_start[data_field_position:data_field_position+data_step]
        total_io_elements_parsed = int(total_io_elements, 16)
        print(f"total I/O elements in record {record_number} = {total_io_elements_parsed}")
        data_field_position += len(total_io_elements)

        try:  
            insertar_datos_gps(io_dict)
        except Exception as e:
            print(f"Error al escribir en JSON o insertar en la base de datos: {e}")

    if props == "SERVER":
        total_records_parsed = int(avl_data_start[data_field_position:data_field_position+2], 16)
        print()
        print(f"total parsed records = {total_records_parsed}")
        print()
        return int(number_of_records)

    else:
        total_records_parsed = int(avl_data_start[data_field_position:data_field_position+2], 16)
        print()
        print(f"total parsed records = {total_records_parsed}")
        print()
        input_trigger()


def coordinate_formater(hex_coordinate):
    coordinate = int(hex_coordinate, 16)
    if coordinate & (1 << 31):
        new_int = coordinate - 2**32
        dec_coordinate = new_int / 1e7
    else:
        dec_coordinate = coordinate / 1e7
    return dec_coordinate

def time_stamper():
    current_server_time = datetime.datetime.now()
    server_time_stamp = current_server_time.strftime('%H:%M:%S %d-%m-%Y')
    return server_time_stamp

def time_stamper_for_json():
    current_server_time = datetime.datetime.now()
    timestamp_utc = datetime.datetime.utcnow()
    server_time_stamp = f"{current_server_time.strftime('%H:%M:%S %d-%m-%Y')} (local) / {timestamp_utc.strftime('%H:%M:%S %d-%m-%Y')} (utc)"
    return server_time_stamp

def device_time_stamper(timestamp):
    timestamp_ms = int(timestamp, 16) / 1000
    timestamp_utc = datetime.datetime.utcfromtimestamp(timestamp_ms)
    utc_offset = datetime.datetime.fromtimestamp(timestamp_ms) - datetime.datetime.utcfromtimestamp(timestamp_ms)
    timestamp_local = timestamp_utc + utc_offset
    formatted_timestamp_local = timestamp_local.strftime("%H:%M:%S %d-%m-%Y")
    formatted_timestamp_utc = timestamp_utc.strftime("%H:%M:%S %d-%m-%Y")
    formatted_timestamp = f"{formatted_timestamp_local} (local) / {formatted_timestamp_utc} (utc)"

    return formatted_timestamp

def record_delay_counter(timestamp):
    timestamp_ms = int(timestamp, 16) / 1000
    current_server_time = datetime.datetime.now().timestamp()
    return f"{int(current_server_time - timestamp_ms)} seconds"

####################################################
###############_PARSE_FUNCTIONS_CODE_###############
####################################################


####################################################


def main():
    # Puedes llamar directamente a start_server_trigger() si ya no necesitas la prueba de acceso a archivos
    # fileAccessTest()
    start_server_trigger()

if __name__ == "__main__":
    main()