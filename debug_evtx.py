from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

campos = set()

with Evtx("Security.evtx") as log:

    for i, record in enumerate(log.records()):

        if i > 500:
            break

        try:
            root = ET.fromstring(record.xml())

            for data in root.findall(".//{*}Data"):

                nombre = data.attrib.get("Name")

                if nombre:
                    campos.add(nombre)

        except:
            pass

for campo in sorted(campos):
    print(campo)