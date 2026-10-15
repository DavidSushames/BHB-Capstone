#!/usr/bin/python
import os
import subprocess
import time
import datetime
from zoneinfo import ZoneInfo
import re

def genReportFunction():
	print ("Analysing file carve...")
	print (" ")

	with open(f'{repDir}/AI_ForemostReport.md', 'w') as f:
		mainPrompt = subprocess.run(
			f"ollama run gemma4-df:latest --verbose --nowordwrap --think=false As a DFIR reporting assistant, generate a forensic summary of the files carved, do NOT nake a template/empty fields, add a cover page, keep it concise, use factual forensic language, time of your report is {date} <{repDir}/output/audit.txt",
			shell = True, capture_output = True, text=True)
		f.write(mainPrompt.stdout)

	p3InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	#print (f"Input tokens for prompt 3: {p3InTok} tokens")

	p3OutTok = int(re.findall(r"^eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	#print (f"Output tokens for prompt 3: {p3OutTok} tokens")

	return p3InTok, p3OutTok

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

#pdf converter/generator

def reportToPDF(reportFile, pdfFile):

	print ("Generating report...")
	print (" ")

	with open(reportFile, "r", encoding="utf-8") as f:
		report = f.read()

	#replace (sub) ANSI artefacts
	report = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', report)

	cleanReport = "cleanReport.md"
	#write to temp md file
	with open(cleanReport, "w", encoding="utf-8") as f:
		f.write(report)

	#pandoc cli conversion
	subprocess.run(
		f"pandoc {cleanReport} -o {pdfFile}",
			shell=True)


fTime = datetime.datetime.now(ZoneInfo('Pacific/Auckland'))
date = (fTime.strftime("%c"))

startTime = time.perf_counter()

print (" ")
print ("\033[92mWELCOME TO NINEMOST V1\033[0m")
print (" ")
print ("LLM-Augmented File Carving Analyis")
print (" ")
 
repDir = os.getcwd()
p3InTok, p3OutTok= genReportFunction()

#convert report to pdf with method
reportToPDF('./AI_ForemostReport.md', './AI_ForemostReport.pdf')

print (f"Report generated in {repDir}/AI_ForemostReport.pdf")
print (" ")

#cleanup
subprocess.run(f"rm AI_ForemostReport.md cleanReport.md",
	shell = True)

endTime = time.perf_counter()
procTime = endTime - startTime

print (f"Report created in {procTime:.2f} seconds")
print (" ")
print (f"Input tokens: {p3InTok} tokens")
print (f"Output tokens: {p3OutTok} tokens")
print (f"Total token cost: {p3InTok + p3OutTok} tokens")
