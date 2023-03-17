#Referencia> documentacion y presentacion en clase
import pefile

from os import listdir
import os
from os.path import isfile, join

mypath = os.getcwd()+'/MALWR'

malware_files = [f for f in listdir(mypath)]

df = []

print(malware_files)

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