"""Dashboard offline: lee los archivos del paquete, clasifica eventos y genera Salidas/dashboard.html.

No abre conexiones ni escanea nada; solo lee CSV/JSON locales. Reutiliza analizador.detectar
(las 6 alertas de referencia) y agrega dos señales del equipo, marcadas como tales:
  - Éxito tras fallos repetidos (correlaciona E0308 con el caso de fallos).
  - Sondeo bloqueado (varios puertos denegados desde un mismo origen).
Las clasificaciones son propuestas para revisión humana; no confirman incidentes.
"""
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import csv, json, importlib.util

ROOT = Path(__file__).resolve().parents[1]

# Supuestos de la extensión del equipo (editables; no son políticas de Kenworth)
SONDEO_MIN_EVENTOS = 5      # denegaciones desde un mismo origen dentro de la ventana
SONDEO_MIN_PUERTOS = 2      # puertos distintos
NIVEL_CRITICIDAD = {"Alta": 3, "Media": 2, "Baja": 1}


def cargar_analizador():
    spec = importlib.util.spec_from_file_location("analizador", ROOT / "06_Laboratorio" / "analizador.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def leer_csv(ruta):
    with (ROOT / ruta).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def nivel(score):
    return "Alta" if score >= 6 else "Media" if score >= 3 else "Baja"


def main():
    analizador = cargar_analizador()
    eventos = leer_csv("02_Datos/eventos_normalizados.csv")
    inventario = leer_csv("02_Datos/inventario_activos.csv")
    cambios = leer_csv("02_Datos/cambios_autorizados.csv")
    cfg = json.loads((ROOT / "03_Configuraciones/parametros_alertas.json").read_text(encoding="utf-8"))
    servidores = json.loads((ROOT / "03_Configuraciones/servidores_prueba.json").read_text(encoding="utf-8"))
    activos = {a["ip_prueba"]: a for a in inventario}
    por_id = {e["evento_id"]: e for e in eventos}
    t = lambda e: datetime.fromisoformat(e["fecha_hora"])
    ventana = timedelta(minutes=cfg["ventana_minutos"])

    def nombre(ip):
        return activos[ip]["nombre_prueba"] if ip in activos else "Externo (etiqueta doc.)"

    # 1) Alertas del analizador base
    alertas = [dict(a, origen_deteccion="Analizador base") for a in analizador.detectar(eventos, cfg)]

    # 2) Contexto: cambio autorizado (CH01) aplicable a un evento
    def cambio_aplicable(e):
        for c in cambios:
            dest = activos.get(e["destino_ip"])
            if (dest and dest["nombre_prueba"] == c["activo"]
                    and e["origen_ip"] == c["origen_autorizado"]
                    and e["usuario_prueba"] == c["usuario_prueba"]
                    and datetime.fromisoformat(c["inicio"]) <= t(e) <= datetime.fromisoformat(c["fin"])):
                return c
        return None

    # 3) Patrones por evento
    patron = {}
    caso_de = {}
    # 3a) fallos repetidos + éxito posterior
    fallos_alerta = [a for a in alertas if a["tipo"] == "Fallos repetidos"]
    extra = []
    for a in fallos_alerta:
        e0 = por_id[a["evento_id"]]
        k = (e0["origen_ip"], e0["destino_ip"], e0["usuario_prueba"])
        t0 = t(e0)
        miembros = [e for e in eventos if e["tipo"] == "autenticacion" and e["resultado"] == "fallo"
                    and (e["origen_ip"], e["destino_ip"], e["usuario_prueba"]) == k and t0 - ventana <= t(e) <= t0 + ventana]
        for e in miembros:
            patron[e["evento_id"]] = "Fallos repetidos"
        for e in eventos:
            if (e["tipo"] == "autenticacion" and e["resultado"] == "exito"
                    and (e["origen_ip"], e["destino_ip"], e["usuario_prueba"]) == k and t0 < t(e) <= t0 + ventana):
                patron[e["evento_id"]] = "Éxito tras fallos"
                extra.append({"evento_id": e["evento_id"], "fecha_hora": e["fecha_hora"], "tipo": "Éxito tras fallos",
                              "motivo": "Acceso exitoso poco después de fallos repetidos con mismo origen, destino y usuario; no demuestra compromiso de credenciales",
                              "disposicion": "Revisar contexto; no confirma incidente", "origen_deteccion": "Extensión del equipo"})
                miembros.append(e)
        for e in miembros:
            caso_de[e["evento_id"]] = ("fallos", k)

    # 3b) sondeo bloqueado
    denegados = defaultdict(list)
    for e in eventos:
        if e["accion"] == "deny":
            denegados[e["origen_ip"]].append(e)
    for origen, lst in denegados.items():
        lst.sort(key=t)
        marcados = set()
        for i, e in enumerate(lst):
            w = [x for x in lst if t(e) <= t(x) <= t(e) + ventana]
            if len(w) >= SONDEO_MIN_EVENTOS and len({x["puerto_destino"] for x in w}) >= SONDEO_MIN_PUERTOS:
                marcados.update(x["evento_id"] for x in w)
        if marcados:
            primero = min(marcados)
            for x in lst:
                if x["evento_id"] in marcados:
                    patron[x["evento_id"]] = "Sondeo bloqueado"
                    caso_de[x["evento_id"]] = ("sondeo", origen)
            n = len(marcados)
            puertos = sorted({x["puerto_destino"] for x in lst if x["evento_id"] in marcados})
            extra.append({"evento_id": primero, "fecha_hora": por_id[primero]["fecha_hora"], "tipo": "Sondeo bloqueado",
                          "motivo": f"{n} conexiones denegadas por R04 desde un mismo origen a varios puertos ({', '.join(puertos)}); el firewall las bloqueó, no prueba intrusión",
                          "disposicion": "Revisar contexto; no confirma incidente", "origen_deteccion": "Extensión del equipo"})

    # 3c) respaldo autorizado, volumen, tráfico esperado
    fp_eventos = set()
    for a in alertas:
        e = por_id[a["evento_id"]]
        if a["tipo"] == "Fuera de horario" and cambio_aplicable(e):
            patron[e["evento_id"]] = "Respaldo en ventana autorizada (CH01)"
            fp_eventos.add(e["evento_id"])
            caso_de[e["evento_id"]] = ("respaldo", e["origen_ip"])
    for e in eventos:
        if int(e["bytes"]) >= cfg["volumen_revision_bytes"]:
            patron[e["evento_id"]] = "Volumen alto a destino externo"
            caso_de[e["evento_id"]] = ("volumen", e["evento_id"])
    for e in eventos:
        if e["evento_id"] not in patron:
            ok = (e["destino_ip"] == "10.60.10.10" and e["puerto_destino"] == "443"
                  and e["accion"] == "allow" and e["regla_id"] == "R01")
            patron[e["evento_id"]] = "Tráfico web esperado (R01)" if ok else "Sin clasificar"

    # 4) Alertas: ids, disposición y falsos positivos propuestos
    # Las alertas base conservan sus IDs (AL001-AL006) para poder compararlas con la referencia;
    # las del equipo continúan la numeración.
    extra.sort(key=lambda a: (a["fecha_hora"], a["evento_id"]))
    for i, a in enumerate(extra, len(alertas) + 1):
        a["alerta_id"] = f"AL{i:03}"
    alertas += extra
    for a in alertas:
        if a["tipo"] == "Fuera de horario" and a["evento_id"] in fp_eventos:
            c = cambio_aplicable(por_id[a["evento_id"]])
            a["estado"] = "Falso positivo (propuesto)"
            a["disposicion"] = f"Cerrar con justificación: actividad cubierta por {c['cambio_id']} ({c['motivo']}). Confirmar con responsable."
        else:
            a["estado"] = "Por revisar"
        a["origen_ip"] = por_id[a["evento_id"]]["origen_ip"]
        a["activo_destino"] = nombre(por_id[a["evento_id"]]["destino_ip"])
    alertas_por_evento = defaultdict(list)
    for a in alertas:
        alertas_por_evento[a["evento_id"]].append(a["alerta_id"])
    # el éxito tras fallos y el sondeo se asocian a todos sus eventos
    # 5) Casos (alertas correlacionadas) y riesgo = impacto x exposición
    casos = []

    def impacto_de(ip):
        a = activos.get(ip)
        return NIVEL_CRITICIDAD[a["criticidad"]] if a else 1

    grupos = defaultdict(list)
    for eid, (tipo, clave) in caso_de.items():
        grupos[(tipo, clave)].append(eid)
    for (tipo, clave), eids in sorted(grupos.items(), key=lambda kv: min(kv[1])):
        eids.sort()
        ev = [por_id[x] for x in eids]
        ids_alerta = sorted({al for x in eids for al in alertas_por_evento.get(x, [])})
        if tipo == "respaldo":
            d = ev[0]["destino_ip"]
            casos.append(dict(titulo="Accesos nocturnos a BACKUP-LAB cubiertos por CH01", estado="Falso positivo (propuesto)",
                eventos=eids, alertas=ids_alerta, activo=nombre(d), origen=ev[0]["origen_ip"], impacto=None, exposicion=None, puntaje=None, nivel=None,
                justificacion="Origen, usuario, activo y horario coinciden con CH01 (02:00-02:30, ADMIN-LAB). Las señales horarias se cierran con justificación.",
                evidencia="CH01 en cambios_autorizados.csv; E0321-E0323 acceso exitoso desde ADMIN-LAB por regla R03.",
                siguiente="Confirmar con Infraestructura y cerrar con la justificación; no se asigna riesgo residual."))
        elif tipo == "volumen":
            e = ev[0]
            imp = impacto_de(e["origen_ip"])
            exp = 2
            casos.append(dict(titulo="Volumen alto desde BACKUP-LAB hacia un destino externo", estado="Por revisar",
                eventos=eids, alertas=ids_alerta, activo=nombre(e["origen_ip"]), origen=e["origen_ip"], impacto=imp, exposicion=exp, puntaje=imp * exp, nivel=nivel(imp * exp),
                justificacion=("Impacto 3: BACKUP-LAB es activo de criticidad alta y su última prueba de restauración no está registrada. "
                               "Exposición 2: el destino es externo y R01 describe tráfico hacia WEB-LAB, pero falta contexto del volumen. "
                               "Ocurre dentro del horario de CH01, que explícitamente no autoriza envío externo."),
                evidencia=f"{e['evento_id']}: {int(e['bytes']):,} bytes por TCP/443 con R01 hacia destino externo; AL de volumen e inconsistencia de registro sobre el mismo evento (se cuenta como un caso, no dos).".replace(",", "."),
                siguiente="Preguntar a Infraestructura qué proceso envió ese volumen y revisar qué regla debería registrarlo. No concluir extracción."))
        elif tipo == "fallos":
            origen, destino, _u = clave
            imp = impacto_de(destino)
            exp = 3
            casos.append(dict(titulo="Fallos repetidos y acceso exitoso posterior hacia DB-LAB", estado="Por revisar",
                eventos=eids, alertas=ids_alerta, activo=nombre(destino), origen=origen, impacto=imp, exposicion=exp, puntaje=imp * exp, nivel=nivel(imp * exp),
                justificacion=("Impacto 3: DB-LAB es activo de criticidad alta. "
                               "Exposición 3: R02 permite Usuarios -> DB-LAB any sin registro, y la configuración indica MFA desactivado, cuentas compartidas y registro centralizado desactivado."),
                evidencia="E0301-E0307 fallos y E0308 éxito (mismo origen, destino y usuario) bajo R02; H01-H03 en hallazgos_iniciales.csv.",
                siguiente="Revisar con Datos/Redes si el usuario reconoce la actividad y restringir R02 con registro (propuesta en Plan de hardening). No demuestra credenciales comprometidas."))
        elif tipo == "sondeo":
            destino = ev[0]["destino_ip"]
            imp = impacto_de(destino)
            exp = 1
            casos.append(dict(titulo="Sondeo de varios puertos hacia DB-LAB bloqueado por el firewall", estado="Por revisar",
                eventos=eids, alertas=ids_alerta, activo=nombre(destino), origen=clave, impacto=imp, exposicion=exp, puntaje=imp * exp, nivel=nivel(imp * exp),
                justificacion="Impacto 3: DB-LAB es activo de criticidad alta. Exposición 1: todas las conexiones fueron denegadas por R04 (cierre por defecto).",
                evidencia=f"{eids[0]}-{eids[-1]}: {len(eids)} denegaciones R04 desde un origen externo a puertos 22, 3389 y 5432.",
                siguiente="Documentar y vigilar repetición; no requiere cambio inmediato porque el bloqueo funcionó."))
    for i, c in enumerate(casos, 1):
        c["caso_id"] = f"C{i:02}"
        for x in c["eventos"]:
            caso_de[x] = c["caso_id"]

    # 6) Filas del tablero de eventos
    filas = []
    for e in eventos:
        eid = e["evento_id"]
        cid = caso_de.get(eid) if isinstance(caso_de.get(eid), str) else ""
        if eid in fp_eventos:
            clase = "Falso positivo (propuesto)"
        elif patron[eid] == "Sondeo bloqueado":
            clase = "Alerta (bloqueado)"
        elif alertas_por_evento.get(eid) or patron[eid] in ("Fallos repetidos", "Éxito tras fallos"):
            clase = "Alerta"
        elif patron[eid] == "Sin clasificar":
            clase = "Sin clasificar"
        else:
            clase = "Normal"
        if e["tipo"] == "autenticacion":
            tipo_txt = "Autenticación " + ("fallida" if e["resultado"] == "fallo" else "exitosa")
        else:
            tipo_txt = "Tráfico " + ("permitido" if e["accion"] == "allow" else "denegado")
        filas.append(dict(id=eid, fecha=e["fecha_hora"].replace("T", " "), tipo=tipo_txt, patron=patron[eid], clase=clase,
                          origen=e["origen_ip"], origen_nombre=nombre(e["origen_ip"]), destino=e["destino_ip"], destino_nombre=nombre(e["destino_ip"]),
                          puerto=int(e["puerto_destino"]), regla=e["regla_id"], usuario=e["usuario_prueba"], bytes=int(e["bytes"]),
                          alertas=alertas_por_evento.get(eid, []), caso=cid))

    resumen = {
        "eventos": len(eventos),
        "alertas": len(alertas),
        "alertas_base": sum(1 for a in alertas if a["origen_deteccion"] == "Analizador base"),
        "falsos_positivos": sum(1 for a in alertas if a["estado"].startswith("Falso")),
        "casos": len(casos),
        "casos_abiertos": sum(1 for c in casos if c["estado"] == "Por revisar"),
        "riesgo": dict(Counter(c["nivel"] for c in casos if c["nivel"])),
        "patrones": dict(Counter(f["patron"] for f in filas)),
        "clases": dict(Counter(f["clase"] for f in filas)),
    }
    datos = {"resumen": resumen, "casos": casos, "alertas": alertas, "eventos": filas,
             "parametros": dict(cfg, sondeo_min_eventos=SONDEO_MIN_EVENTOS, sondeo_min_puertos=SONDEO_MIN_PUERTOS),
             "servidores": servidores}

    dest = ROOT / "Salidas"
    dest.mkdir(exist_ok=True)
    (dest / "dashboard_datos.json").write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    with (dest / "eventos_clasificados.csv").open("w", encoding="utf-8-sig", newline="") as f:
        campos = ["id", "fecha", "tipo", "patron", "clase", "origen", "origen_nombre", "destino", "destino_nombre", "puerto", "regla", "usuario", "bytes", "alertas", "caso"]
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for r in filas:
            w.writerow(dict(r, alertas=";".join(r["alertas"])))
    plantilla = (ROOT / "06_Laboratorio" / "dashboard_plantilla.html").read_text(encoding="utf-8")
    blob = json.dumps(datos, ensure_ascii=False).replace("</", "<\\/")
    (dest / "dashboard.html").write_text(plantilla.replace("/*__DATOS__*/null", blob), encoding="utf-8")
    print(json.dumps(resumen, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
