#Referencia> documentacion y presentacion en clase
import pefile
import subprocess

from os import listdir
import os
from os.path import isfile, join

mypath = os.getcwd()+'/MALWR'

malware_files = [f for f in listdir(mypath)]

df = []

#desempaquetando archivos con UPX
for i in malware_files:
  subprocess.run(['upx','-d',mypath+'/'+i])

#mostrar los nombres de sections
for malware in malware_files:
    print(malware)
    pe = pefile.PE(mypath+'/'+malware)
    for section in pe.sections:
        print(section.Name)


'''
pe = pefile.PE(executable)


for section in pe.sections:
  print(section.Name, hex(section.VirtualAddress),
    hex(section.Misc_VirtualSize), section.SizeOfRawData )'''


