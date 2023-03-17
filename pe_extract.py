#Referencia> documentacion y presentacion en clase
import pefile
import subprocess
import pandas as pd
from os import listdir
import os
import csv
from os.path import isfile, join

mypath = os.getcwd()+'/MALWR'

malware_files = [f for f in listdir(mypath)]

df = []

#desempaquetando archivos con UPX
for i in malware_files:
  subprocess.run(['upx','-d',mypath+'/'+i])

#mostrar los nombres de sections
for malware in malware_files:
    info_malware= {}

    pe = pefile.PE(mypath+'/'+malware)
    for section in pe.sections:
        #print(section.Name.decode(),str(section.Name).split("'")[1].split("\\")[0])
        info_malware  = {
                          section.Name.strip(b'\00').decode(): True,
                          section.Name.strip(b'\00').decode()+'vAddress':section.VirtualAddress,
                          section.Name.strip(b'\00').decode()+'vSize':section.Misc_VirtualSize,
                          section.Name.strip(b'\00').decode()+'rSize': section.SizeOfRawData
                        }

    #Obteniendo dlls y llamadas a APIS
    for entry in pe.DIRECTORY_ENTRY_IMPORT:

        info_malware[entry.dll.decode()] = True

    for function in entry.imports:
        info_malware[function.name.decode()] = True

    df.append(info_malware)

df = pd.DataFrame(df)


print(df.head(15))
print(df.shape)

#https://towardsdatascience.com/how-to-export-pandas-dataframe-to-csv-2038e43d9c03
df.to_csv('malware_dataset.csv', index=False)
