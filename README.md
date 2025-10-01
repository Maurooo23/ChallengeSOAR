# ChallengeSOAR
Este proyecto simula una especie de soar para la ingestión, enriquecimiento, triage y respuesta de incidentes de ciberseguridad. Ademas procesa alertas en formato JSON, aplica reglas de enriquecimiento a traves de proveedor hardcodiados, calcula severidad y técnicas MITRE, y genera salidas en JSON, Markdown y logs.


## Funcionalidades

1. **Ingesta:**  
   mapea la alerta original e inicializa un incidente con indicadores (IP, dominios, URLs, hashes, etc.) dependiendo de lo que extraiga del json inicial.

2. **Enrichment:**  
   Recorre archivos (`.json`) de X proveedores TI y agrega informacion adicional al incidente por cada IOC encontrado.

3. **Triage:**  
   - Calcula severidad según tipo de alerta (Malware, Phishing, C2, etc.).  
   - Ajusta puntajes según verdictos de IOCs.  
   - Valida si la informacion pertenece a listas blancas.  
   - Asigna criticidades a la alerta. (`Low`, `Medium`, `High`, `Critical`, `Suppressed`).  
   - Agrega tags y mapeo MITRE ATT&CK.

4. **Response:**  
   Si la severidad ≥ 70 y el dispositivo no está suprimido, ejecuta acción de aislamiento y lo deja en `out/isolation.log`.
   Ademas de entregar la informacion obtenida, resumida en un archivo .json y mediante un template para lectura de analitas.

5. **Outputs:**  
   - Incidente en JSON → `out/incidents/<incident_id>.json`  
   - Resumen en Markdown → `out/summaries/<incident_id>.md`  
   - Log de aislamiento → `out/isolation.log`

6. **Timeline:**  
   Cada etapa (ingesta, enrichment, triage, response) queda registrada con fecha/hora y detalles.

---

##  Instalación

Clonar el repositorio y luego instalar dependencias:

```bash
pip install -r requirements.txt
```

##  Uso

python main.py alerts/sentinel.json

