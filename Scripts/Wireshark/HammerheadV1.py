#!/usr/bin/python
import os
import subprocess
import time
import datetime
from zoneinfo import ZoneInfo
import re

def genReportFunction():

#Pcap-CSV conversion
	print (f"Converting file: {targetScan} to {filePrefix}.csv")
	subprocess.run(f"tshark -r {targetScan} -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info > {filePrefix}.csv",
		shell = True)
	print (" ")
	
#file chunking
	print (f"Chunking file: {filePrefix}.csv")
	subprocess.run(f"split -n l/2 {filePrefix}.csv",
		shell = True)
#process chunk 1
	chunkStats1 = subprocess.run("cat ./xaa | ollama run gemma4-df:latest --verbose --nowordwrap --think=false summarize key forensic information in this section of a pcap, so it can be consolidated later into a full report, display the range of packets >./scanChunk1.md",
		shell = True, capture_output = True, text = True)
	print (" ")
#calctokens1
	#print (chunkStats1.stderr)
	p1InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Input tokens for prompt 1: {p1InTok} tokens")

	p1OutTok = int(re.findall(r"^eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 1: {p1OutTok} tokens")
#process chunk 2
	chunkStats2 = subprocess.run("cat ./xab | ollama run gemma4-df:latest --verbose --nowordwrap --think=false summarize key forensic information in this section of a pcap, so it can be consolidated later into a full report, display the range of packets  >./scanChunk2.md",
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
	with open('./AI_WiresharkReport.md', 'w') as f:
		mainPrompt = subprocess.run(
			f"ollama run gemma4-df:latest --verbose --nowordwrap --think=false As a PCAP analysis assistant, generate a DFIR report of these packet summaries in clean markdown formatting, include key findings, dont repeat information, keep it concise, use factual language, time of the report is {date}, name of the subject pcap is {targetScan} <./scanSum.md",
				shell = True, capture_output = True, text=True)
		f.write(mainPrompt.stdout)
#calctokens3
	#print (mainPrompt.stderr)
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
	#replace unwanted markdown artefacts
#	report = re.sub(r'(?m

	cleanReport = "cleanReport.md"
	#write to temp md file
	with open(cleanReport, "w", encoding="utf-8") as f:
		f.write(report)

	#pandoc cli conversion
	subprocess.run(
		f"pandoc {cleanReport} -o {pdfFile}",
			shell=True)


print (" ")
print ("\033[92mWELCOME TO HAMMERHEAD V1\033[0m")
print (" ")
print ("LLM-Augmented Pcap Analysis")
print (" ")
print ("Enter the name of the Pcap you want to examine:")
targetScan = input()

filePrefix = re.sub(r"\.[^.]+$","", targetScan)

repDir = os.getcwd()

fTime = datetime.datetime.now(ZoneInfo('Pacific/Auckland'))
date = (fTime.strftime("%c"))

startTime = time.perf_counter()

print (" ")

totalInTok, totalOutTok = genReportFunction()

#convert report to pdf with method
reportToPDF('./AI_WiresharkReport.md', './AI_WiresharkReport.pdf')

print (" ")
print (f"Report generated in {repDir}/AI_WiresharkReport.pdf")
print (" ")

#cleanup
subprocess.run(f"rm ./AI_WiresharkReport.md cleanReport.md xaa xab scanChunk1.md scanChunk2.md scanSum.md",
	shell = True)

endTime = time.perf_counter()
procTime = endTime - startTime

print (f"Report created in {procTime:.2f} seconds") 
print (" ")
print (f"Total input tokens: {totalInTok} tokens")
print (f"Total output tokens: {totalOutTok} tokens")
print (f"Total token cost: {totalInTok + totalOutTok} tokens")
