#!/usr/bin/python
import os
import subprocess
import time
def genReportFunction():
	subprocess.run(f"split -n 1/2 {repDir}/output/audit.txt | ollama run gemma4:26b --think=false summarize key  information in this section, foremost version, time, and target disk image >{repDir}/output/auditChunk1.txt",
		shell = True)
	subprocess.run(f"split -n 2/2 {repDir}/output/audit.txt | ollama run gemma4:26b --think=false summarize key information in this section,  >{repDir}/output/auditChunk2.txt",
		shell = True)
	subprocess.run(f"cat {repDir}/output/auditChunk1.txt {repDir}/output/auditChunk2.txt > {repDir}/output/auditSum.txt",
		shell = True)
	subprocess.run(f"rm {repDir}/output/auditChunk1.txt {repDir}/output/auditChunk2.txt",
		shell = True)

	print ("File chunking completed")

	with open(f'{repDir}/AI_Report.txt', 'w') as f:
		subprocess.run(
			f"ollama run gemma4:26b --think=false As a DFIR reporting assistant, generate a forensic summary of the files carved, do NOT nake a template/empty fields, add a cover page, keep it concise, use factual forensic language <{repDir}/output/auditSum.txt",
			shell = True, stdout=f, text=True)

#def pngFunction():
#	with open(f'{repDir}/AI_Report.txt', 'r') as f:
#		report = f.read()
#	with open(f'{repDir}/AI_Report.txt', 'w') as f:
#		subprocess.run(['ollama',
#			'run',
#			'gemma4:26b',
#			'--think=false',
#			f'update this forensic report with an extremely short desription of the image with the name of the png file, RETURN THE ENTIRE REPORT with your part added formatted to fit the report, below the evidence section {report}',
#			f'./{png}'], stdout=f, text=True)

startTime = time.perf_counter()

print (" ")
print ("WELCOME TO NINEMOST")
print (" ")
print ("The premier in file carving analysis")
print (" ")
 
repDir = os.getcwd()
genReportFunction()

#os.chdir(f"{repDir}/output/png")
#png = subprocess.run(['ls'], capture_output=True).stdout.decode()
#pngFunction()

print (" ")
print (f"Report generated in {repDir}/AI_Report.txt")
print (" ")

endTime = time.perf_counter()
procTime = endTime - startTime

print(f"Report created in {procTime:.2f} seconds")
