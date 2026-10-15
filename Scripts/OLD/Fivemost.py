#!/usr/bin/python
import os
import subprocess

def jpg_function():
	with open(f'{repDir}/AI_Report.txt', 'a') as f:
		subprocess.run(['ollama',
			'run',
			'gemma4:26b',
			'--think=false',
			'Describe in one sentence a short description of the image',
			f'./{jpg}'], stdout=f, text=True)
def png_function():
        with open(f'{repDir}/AI_Report.txt', 'a') as f:
                subprocess.run(['ollama',
                        'run',
                        'gemma4:26b',
                        '--think=false',
                        'Describe in one sentence a short description of the image',
                        f'./{png}'], stdout=f, text=True)
jpg = "jpg"
png = "png"

print (" ")
print ("WELCOME TO FIVEMOST")
print (" ")
print ("The premier in file carving analysis")
print (" ")
 
repDir = os.getcwd()
os.chdir("output")
os.chdir("jpg")

jpg = subprocess.run(['ls'], capture_output=True).stdout.decode()
jpg_function()

os.chdir(f"{repDir}/output/png")
png = subprocess.run(['ls'], capture_output=True).stdout.decode()
png_function()
