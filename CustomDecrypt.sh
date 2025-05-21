#!/bin/sh

NTFY_URL="$1"
PUBLIC_KEY_PATH="$2"

# Configura el FallbackDNS de Resolvd con la misma IP que la gateway de TUN (VPN)
FORCE_FALLBACK_DNS_VPN=1
# Nombre del servicio de Openvpn que debe ser esperado antes de realizar peticiones a la web
OPENVPN_SERVICE_NAME="Openvpn.service"

# Para destrabar Stage2 en caso que las unidades ya esten descifradas
all_luks_ready=1
for device in $(lsblk -rno NAME,TYPE | grep "part" | cut -d ' ' -f1); do
    # Verificar si la partición tiene LUKS
    if cryptsetup luksUUID "/dev/$device" &>/dev/null; then
        device_uuid=$(cryptsetup luksUUID "/dev/$device")
        # Si, al menos, una particion LUKS no esta en el mapper, podemos asumir que las unidades aun no estan totalmente destrabadas
        if ! ls /dev/mapper | grep -q "$device_uuid"; then
            all_luks_ready=0
        fi
    fi
done
if [[ "$all_luks_ready" -eq 1 ]]; then
    echo "Partitions ALREADY unlocked"
    systemctl stop cryptsetup.target
    exit 0
fi

# Para parar el proceso si en esta ejecucion de Stage1, CustomDecrupt.sh ya fue ejecutado
CONTROL_FILE="/etc/nixos/control.txt"
if [[ -f "$CONTROL_FILE" ]]; then
  echo "CustomDecrypt alerdy runed, reboot needed..."
  exit 0
fi
echo "CustomDecrypt" > "$CONTROL_FILE"

# En caso de usar OpenVPN, esperamos que el tunel esta listo antes de proseguir
# Verificamos el caso donde OpenVPN esta declarado como servicio pero descativado (masked) y el caso donde, simplemente, no esta
if systemctl list-unit-files --type=service | grep -q "^$OPENVPN_SERVICE_NAME"; then
  status_openvpn=$(systemctl is-enabled "$OPENVPN_SERVICE_NAME" 2>/dev/null)
  if [ "$status_openvpn" != "masked" ]; then
    echo "OpenVPN detected... waiting for TUN to be ready..."
    while true; do
      if ip route | grep -q 'dev tun[0-9]'; then
        echo "TUN detected..."

		# Configura el FallbackDns para asegurar que se use el DNS de la VPN
        if [[ "$FORCE_FALLBACK_DNS_VPN" -eq 1 ]]; then
          vpn_gateway_ip=$(ip route | grep -E 'via .* dev tun[0-9]+' | sed -E 's/.*via ([0-9.]+) .*/\1/' | head -n1)
          if [[ -z "$vpn_gateway_ip" ]]; then
            echo "Failed to obtain the gateway IP of TUN"
          fi
          if grep -q "^FallbackDNS=" /etc/systemd/resolved.conf; then
            sed -i "s/^FallbackDNS=.*/FallbackDNS=$vpn_gateway_ip/" /etc/systemd/resolved.conf
          else
            echo "FallbackDNS=$vpn_gateway_ip" >> /etc/systemd/resolved.conf
          fi
          systemctl restart systemd-resolved
          echo ".FallbackDNS configured..."
        fi

        echo "...continuing with CustomDecrypt"
        sleep 3
        break
      fi
      sleep 1
    done
  fi
else
  echo "OpenVPN not detected on the system or is disabled (masked). Continuing with CustomDecrypt."
fi

stop_crypt=0

# Generamos claves efimeras
ephemeral_private_key=$(openssl genpkey -algorithm RSA -outform PEM -pkeyopt rsa_keygen_bits:2048 2>/dev/null)
ephemeral_public_key=$(echo "$ephemeral_private_key" | openssl rsa -pubout -outform PEM 2>/dev/null)

# Ciframos la clave efimera publica
crypt_ephemeral_public_key=$(echo "$ephemeral_public_key" | openssl pkeyutl -encrypt -pubin -inkey "$PUBLIC_KEY_PATH" -pkeyopt rsa_padding_mode:oaep | base64 -w 0)

# Enviamos clave a NTFY
curl -s -d "NEED PASS" "$NTFY_URL" > /dev/null 2>&1
sleep 2
curl -s -d "QUERY:${crypt_ephemeral_public_key}" "$NTFY_URL" > /dev/null 2>&1
sleep 3

# Esperamos respuesta
while IFS= read -r line; do
    if [[ "$line" == RESPONSE:* ]]; then
        message="${line#RESPONSE:}"
        # Validar si message es Base64 antes de decodificar
        if echo "$message" | base64 -d >/dev/null 2>&1; then
            decrypted_message=$(echo "$message" | base64 -d | openssl pkeyutl -decrypt -inkey <(echo "$ephemeral_private_key") -pkeyopt rsa_padding_mode:oaep 2>/dev/null)
   	    if [ $? -ne 0 ]; then
    		echo "Error: Could not decrypt the message"
	    else
		# Extraer contraseña y checksum
			if [[ $decrypted_message =~ ^PASS:([^:]+):CHECKSUM:([^:]+)$ ]]; then
				password="${BASH_REMATCH[1]}"
				checksum="${BASH_REMATCH[2]}"

				# Calcular SHA256 de la contraseña y compara con el checksum
				password_hash=$(echo -n "$password" | sha256sum | cut -d ' ' -f1)
				if [[ "$password_hash" == "$checksum" ]]; then

					# Para cada unidad con LUKS, usamos la clave para descifrar
					for device in $(lsblk -rno NAME,TYPE | grep "part" | cut -d ' ' -f1); do
						# Verificar si la partición es LUKS
						if cryptsetup luksUUID "/dev/$device" &>/dev/null; then
							echo "Device with LUKS found: /dev/$device"
							device_uuid=$(cryptsetup luksUUID "/dev/$device")
							echo "$password" | cryptsetup luksOpen "/dev/$device" "$device_uuid"
							sleep 5
							if ls /dev/mapper | grep -q "$device_uuid"; then
								echo "Ok: $device_uuid in MAPPER"
								stop_crypt=1
							else
								echo "Error: $device_uuid not in MAPPER"
								stop_crypt=0
							fi

						fi
					done

					# Confirmacion que todos los LUKS estan listos
					if [[ "$stop_crypt" -eq 1 ]]; then
						curl -s -d "OK" "$NTFY_URL" > /dev/null 2>&1
					fi

				else
					echo "Error: Checksum does not match"
				fi
			else
				echo "Error: The decrypted message does not have the expected format"
			fi
	    fi
        else
            echo "Warning: 'message' is not valid Base64. Skipping..."
        fi
        break
    fi
done < <(curl -N -s "$NTFY_URL/raw")

unset message
unset password
unset checksum
unset password_hash
unset ephemeral_private_key
unset ephemeral_public_key
unset crypt_ephemeral_public_key
unset decrypted_message

if [[ "$stop_crypt" -eq 1 ]]; then
    #Si el "emergency mode" AUN NO esta activo, podemos cerrar directamente cryptsetup.target para destrabar stage2
    #En caso contrario, debemos forzar un reinicio de systemD con systemctl default. Luego de esto si podremos estrabar stage2 deteniendo cryptsetup.target
    status=$(systemctl is-active emergency.service)
    if [ "$status" == "inactive" ]; then
        systemctl stop cryptsetup.target
        #Damos un tiempo para escapar al caso donde justo "emergency mode" pasa a "activo" durante este proceso y debemos reiniciar 
        sleep 60
    fi
    systemctl default
fi
