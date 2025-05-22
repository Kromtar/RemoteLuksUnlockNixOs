Estos son los archivos de configuraci+on y Scripts usados en el articulo: [Desbloqueo remoto LUKS, una solución innovadora - NixOS](https://dev.to/federico_jensen/desbloqueo-remoto-luks-una-solucion-innovadora-nixos-1g25)
Los videos relacionados a este articulo son: [Desbloqueo remoto LUKS -NixOS- Introducción](https://odysee.com/@Federico_Jensen:7/desbloqueo-remoto-luks-nixos-intro:2) y [Desbloqueo remoto LUKS -NixOS- Implementación](https://odysee.com/@Federico_Jensen:7/desbloqueo_remoto_luks-nixos-implementacion:9)

Este proyecto consiste en tener una forma de desbloquear remotamente unidades lógicas aseguradas con LUKS, específicamente en el contexto de la distribución de Linux NixOS.
La propuesta utiliza Ntfy.sh para comunicar el proceso de stage 1 del arranque de NixOS con un dispositivo remoto autorizado, por ejemplo, un celular. Es a este dispositivo remoto al que el sistema solicita que se digite la clave LUKS.
El sistema contempla el uso de distintas capas de cifrado para mantener la seguridad de la implementación. También se propone el uso de OpenVPN para agregar una capa de anonimato a la comunicación. 
