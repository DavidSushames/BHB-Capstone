#!/usr/bin/python
import os
import subprocess
import time
import re
def genReportFunction():
#file chunking
	print (f"Chunking file: {targetScan}")
	chunkStats1 = subprocess.run(f"split -n 1/2 ./{targetScan} | ollama run gemma4:26b --verbose --think=false summarize key  information in this section, so it can be consolidated later into a full report >./scanChunk1.txt",
		shell = True, capture_output = True, text = True)
	print (" ")
#calctokens1
	#print (chunkStats1.stderr)
	p1InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Input tokens for prompt 1: {p1InTok} tokens")

	p1OutTok = int(re.findall(r"^eval count:\s+(\d+)", chunkStats1.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 1: {p1OutTok} tokens")

	chunkStats2 = subprocess.run(f"split -n 2/2 ./{targetScan} | ollama run gemma4:26b --verbose --think=false summarize key information in this section, so it can be consolidated later into a full report  >./scanChunk2.txt",
		shell = True, capture_output = True, text = True)
	print (" ")
#calctokens2
	#print (chunkStats2.stderr)
	p2InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", chunkStats2.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 2: {p2InTok} tokens")

	p2OutTok = int(re.findall(r"^eval count:\s+(\d+)", chunkStats2.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 2: {p2OutTok} tokens")

	subprocess.run(f"cat ./scanChunk1.txt ./scanChunk2.txt > ./scanSum.txt",
		shell = True)
	subprocess.run(f"rm ./scanChunk1.txt ./scanChunk2.txt",
		shell = True)

	print (" ")
	print ("File chunking completed")
	print (" ")
#report generation
	with open('./AI_NmapReport.txt', 'w') as f:
		mainPrompt = subprocess.run(
			f"ollama run gemma4:26b --verbose --think=false As a DFIR reporting assistant, generate a forensic summary of the network scanned, do NOT make a template/empty fields, add a cover page, keep it concise, use factual forensic language <./scanSum.txt",
				shell = True, capture_output = True, text=True)
		f.write(mainPrompt.stdout)

	p3InTok = int(re.findall(r"^prompt eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	print (f"Input tokens for prompt 3: {p3InTok} tokens")

	p3OutTok = int(re.findall(r"^eval count:\s+(\d+)", mainPrompt.stderr, re.MULTILINE)[0])
	print (f"Output tokens for prompt 3: {p3OutTok} tokens")

	totalInTok = (p1InTok + p2InTok + p3InTok)
	totalOutTok = (p1OutTok + p2OutTok + p3OutTok)
	return totalInTok, totalOutTok
print (" ")
print ("\033[92mWELCOME TO SILENT CARTOGRAPHER V1\033[0m")
print (" ")
print ("LLM-Augmented Nmap Scan Analysis")
print (" ")
print ("Enter the name of the XML/JSON you want to examine:")
targetScan = input()

repDir = os.getcwd()
startTime = time.perf_counter()
print (" ")
totalInTok, totalOutTok = genReportFunction()

print (" ")
print (f"Report generated in {repDir}/AI_NmapReport.txt")
print (" ")

endTime = time.perf_counter()
procTime = endTime - startTime

print (f"Report created in {procTime:.2f} seconds") 
print (" ")
print (f"Total input tokens: {totalInTok} tokens")
print (f"Total output tokens: {totalOutTok} tokens")
print (f"Total token cost: {totalInTok + totalOutTok} tokens")
