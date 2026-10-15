#!/usr/bin/python
import os
import subprocess
import time
import datetime
from zoneinfo import ZoneInfo
import re

def genReportFunction():

#XML-TOON conversion
	print (f"Converting file: {targetScan} to {filePrefix}.toon")
	subprocess.run(f"toon-parse --from xml --to toon -i {targetScan} -o {filePrefix}.toon",
		shell = True)
	print (" ")
	
#file chunking
	print (f"Chunking file: {filePrefix}.toon")
	subprocess.run(f"split -n l/2 {filePrefix}.toon",
		shell = True)
	chunkStats1 = subprocess.run("ollama run gemma4-df:latest --verbose --nowordwrap --think=false summarize key  information in this section of an nmap output, so it can be consolidated later into a full report <./xaa >./scanChunk1.md",
		shell = True, capture_output = True, text = True)
	print (" ")
#calctokens1
	#print (chunkStats1.stderr)
	p1InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Input tokens for prompt 1: {p1InTok} tokens")

	p1OutTok = int(re.findall(r"^eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 1: {p1OutTok} tokens")

	chunkStats2 = subprocess.run("ollama run gemma4-df:latest --verbose --nowordwrap --think=false summarize key information in this section of an nmap output, so it can be consolidated later into a full report <./xab  >./scanChunk2.md",
		shell = True, capture_output = True, text = True)
	print (" ")
#calctokens2
	#print (chunkStats2.stderr)
	p2InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", chunkStats2.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 2: {p2InTok} tokens")

	p2OutTok = int(re.findall(r"^eval count:\s+(\d+)", chunkStats2.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 2: {p2OutTok} tokens")

	subprocess.run(f"cat ./scanChunk1.md ./scanChunk2.md > ./scanSum.md",
		shell = True)

	print (" ")
	print ("File chunking completed")
	print (" ")
#report generation
	with open('./AI_NmapReport.md', 'w') as f:
		mainPrompt = subprocess.run(
			f"ollama run gemma4-df:latest --verbose --nowordwrap --think=false As an Nmap analysis assistant, generate a report of the key findings, vulnerabilities, keep it concise, use factual language, time of the report is {date}, name of the subject Nmap scan is {targetScan} <./scanSum.md",
				shell = True, capture_output = True, text=True)
		f.write(mainPrompt.stdout)
#calctokens3
	p3InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	print (f"Input tokens for prompt 3: {p3InTok} tokens")

	p3OutTok = int(re.findall(r"^eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 3: {p3OutTok} tokens")

	totalInTok = (p1InTok + p2InTok + p3InTok)
	totalOutTok = (p1OutTok + p2OutTok + p3OutTok)
	return totalInTok, totalOutTok
	
#pdf converter/generator

def reportToPDF(reportFile, pdfFile):

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
print (" ")
print ("\033[92mWELCOME TO SILENT CARTOGRAPHER V1\033[0m")
print (" ")
print ("LLM-Augmented Nmap Scan Analysis")
print (" ")
print ("Enter the name of the Nmap scan you want to examine:")
targetScan = input()

filePrefix = re.sub(r"\.[^.]+$","", targetScan)

repDir = os.getcwd()

fTime = datetime.datetime.now(ZoneInfo('Pacific/Auckland'))
date = (fTime.strftime("%c"))

startTime = time.perf_counter()

print (" ")

totalInTok, totalOutTok = genReportFunction()

#convert report to pdf with method
reportToPDF('./AI_NmapReport.md', './AI_NmapReport.pdf')

print (" ")
print (f"Report generated in {repDir}/AI_NmapReport.pdf")
print (" ")

#cleanup
subprocess.run(f"rm ./AI_NmapReport.md cleanReport.md xaa xab scanChunk1.md scanChunk2.md scanSum.md {filePrefix}.toon",
	shell = True)

endTime = time.perf_counter()
procTime = endTime - startTime

print (f"Report created in {procTime:.2f} seconds") 
print (" ")
print (f"Total input tokens: {totalInTok} tokens")
print (f"Total output tokens: {totalOutTok} tokens")
print (f"Total token cost: {totalInTok + totalOutTok} tokens")
