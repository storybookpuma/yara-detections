# YARA Detections: Reglas y Cacería (Windows/Linux/ETW)

Este proyecto resume el uso práctico de YARA para detección de malware y hunting. Incluye estructura de reglas, generación con yarGen, uso en Windows, Linux, y con ETW (SilkETW).

## ¿Qué es YARA?
Herramienta para detectar patrones en archivos y memoria mediante reglas. Útil para detectar malware, IOCs y artefactos durante IR/hunting.


## Estructura de una regla YARA
```yara
rule my_rule {
  meta:
    author = "Name"
    description = "example"
  strings:
    $s1 = "test"
    $s2 = "rule"
  condition:
    all of them
}
```

Ejemplo práctico (WannaCry):
```yara
rule Ransomware_WannaCry {
  meta:
    author = "Madhukar Raina"
  strings:
    $s1 = "tasksche.exe" fullword ascii
    $s2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
    $s3 = "mssecsvc.exe" fullword ascii
  condition:
    all of them
}
```

## Desarrollando reglas YARA
- Identificar artefactos (strings, metadatos, imphash, PE headers)
- Crear reglas incrementales (evitar FP, usar condiciones combinadas)
- Probar en muestras/control del entorno

UPX como indicador:

![Strings/UPX](./images/Pasted%20image%2020250805085837.png)

Regla simple UPX:
```yara
rule UPX_packed_executable {
  strings:
    $a = "UPX0"
    $b = "UPX1"
    $c = "UPX2"
  condition:
    2 of ($a,$b,$c)
}
```

Muestras y reglas generadas:

![Reglas generadas](./images/Pasted%20image%2020250805090208.png)

## yarGen: generación asistida de reglas
- Repositorio: Neo23x0/yarGen
- Flujo: actualizar base → extraer strings de muestra → generar `.yar` → validar

![yarGen update](./images/Pasted%20image%2020250805094538.png)
![yarGen output](./images/Pasted%20image%2020250805094908.png)
![yarGen file](./images/Pasted%20image%2020250805094951.png)
![yara match](./images/Pasted%20image%2020250805095157.png)

## Ejemplos
- Ejemplo 1: ZoxPNG (strings + imphash)

![strings legit.exe](./images/Pasted%20image%2020250805095451.png)

- Ejemplo 2: Turla Neuron (.NET classes/functions)
```yara
rule neuron_functions_classes_and_vars {
  strings:
    $class1 = "StorageUtils" ascii
    $func1 = "AddConfigAsString" ascii
    $dotnetMagic = "BSJB" ascii
  condition:
    $dotnetMagic and 6 of them
}
```

## Hunting Evil with YARA (Windows)
- Analizar binarios con HxD

![HxD ruta](./images/Pasted%20image%2020250805115708.png)


Ejemplo (Dharma):

![coincidencias yara](./images/Pasted%20image%2020250805120349.png)

## Escaneo de procesos con YARA (Windows)
- Inyección controlada y escaneo por regla de shellcode de Meterpreter

![inyección proceso](./images/Pasted%20image%2020250805121216.png)
![match proceso padre](./images/Pasted%20image%2020250805121940.png)
![match proceso hijo](./images/Pasted%20image%2020250805122307.png)

## YARA + ETW con SilkETW
- Proveedores: PowerShell, DNS-Client, Kernel-Process, etc.
- Uso: filtrar eventos en tiempo real con YARA (flag `-y`, salida JSON)

![SilkETW PS](./images/Pasted%20image%2020250805123645.png)
![match PS](./images/Pasted%20image%2020250805124450.png)
![DNS ETW](./images/Pasted%20image%2020250805124944.png)
![hex sandbox](./images/Pasted%20image%2020250805125253.png)

## YARA en Linux (memoria y Volatility)
- Escaneo de imágenes de memoria (`--print-strings`)
- Integración directa con Volatility `yarascan`

![yara memoria](./images/Pasted%20image%2020250806101228.png)
![volatility patrón](./images/Pasted%20image%2020250806101723.png)
![yarascan -y](./images/Pasted%20image%2020250806102218.png)
![yarascan salida](./images/Pasted%20image%2020250806102517.png)
![preguntas](./images/Pasted%20image%2020250806102913.png)


## Requisitos
- YARA (win/linux)
- HxD o strings/hexdump
- SilkETW (ETW)
- Volatility (opcional)

