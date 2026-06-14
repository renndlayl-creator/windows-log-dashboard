from Evtx.Evtx import Evtx
import pandas as pd
import xml.etree.ElementTree as ET

rows = []

print("Leyendo EVTX...")

with Evtx("Security.evtx") as log:

    for record in log.records():

        try:

            root = ET.fromstring(record.xml())

            event_id = root.find(".//{*}EventID")
            timestamp = root.find(".//{*}TimeCreated")
            computer = root.find(".//{*}Computer")

            username = ""
            ip_address = ""
            logon_type = ""

            for data in root.findall(".//{*}Data"):

                name = data.attrib.get("Name", "")
                value = data.text if data.text else ""

                if name == "TargetUserName":
                    username = value

                elif name == "IpAddress":
                    ip_address = value

                elif name == "LogonType":
                    logon_type = value

            rows.append({
                "TimeCreated": timestamp.attrib.get("SystemTime") if timestamp is not None else "",
                "EventID": int(event_id.text) if event_id is not None else 0,
                "Computer": computer.text if computer is not None else "",
                "TargetUserName": username,
                "IpAddress": ip_address,
                "LogonType": logon_type
            })

        except Exception:
            continue

df = pd.DataFrame(rows)

print("Eventos extraídos:", len(df))

df.to_csv(
    "events.csv",
    index=False
)

print("events.csv generado")