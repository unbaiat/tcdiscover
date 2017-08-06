#!/usr/bin/python

"""
TCDiscover
A python script to search .DD drives images or folders for potential Truecrypt containers.

For options, see usage().

License: GNU GPL v3

Authors: 
	SaintGosu [at] gmail [dot] com
	tdean87 [at] gmail [dot] com
"""


import string, getopt, sys, os, array, math, re
from datetime import datetime

def initializeHeaders(configFile):
	""" Creates the magic header list based on defaults or based on a scalpel/foremost config file """
	# using global variable for now, maybe change this later...
	global headers
	if configFile == "":
		# Use standard list of common headers (pkzip, jpg, png)
		headervals = ("504b0304","ffd8ff","89504e470D0a1a0a")
		headers = []
		for header in headervals:
			headers.append(re.compile(header))
		
	else:
		lines = open(configFile).readlines()	
		headervals = [standardizeHex(line.split()[3]) for line in lines if line[0] != "#" and line != "\n"]
		headers = []
		for header in headervals:
			headers.append(re.compile(header))

def standardizeHex(s):
	""" Converts any pieces of the scalpel/foremost config file from ascii to hex """
	finalString, x = "", 0
	
	while x < len(s):
		if s[x:x+2] == "\\x": # found a hex value
			finalString += s[x+2:x+4]
			x += 4
		elif s[x] == "?": #translate the wildcard correctly
			finalString += "[0-9a-f]"
			x += 1
		else: # a non hex value, so encode it
			finalString += s[x].encode("hex")
			x += 1
			
	return finalString

def commonHeader(data):
	""" Search data for common file headers """
	hexval = str(data.encode("hex")).lower()
	for header in headers:
		if header.match(hexval):
			return True
	
	return False

def entropy(data):
	"""Calculate the entropy of a chunk of data."""

	if len(data) == 0 or commonHeader(data):
		return 0.0
        
	occurences = array.array('L', [0]*256)
        
	for x in data:
		occurences[ord(x)] += 1
        
	entropy = 0
	for x in occurences:
		if x:
			p_x = float(x) / len(data)
			entropy -= p_x*math.log(p_x, 2)
        
	return entropy

def searchLeft(imageFile, entropyLimit, currentPosition, blockSize):
	""" Return the run of contiguous blocks to the left in imageFile 
		over entropyLimit, starting at currentPosition.
	"""
	blockRun = 0
	
	while currentPosition > 1:
		
		currentPosition -= 1
		
		imageFile.seek(currentPosition*blockSize)
		block = imageFile.read(blockSize)
		
		if entropy(block) > entropyLimit:
			blockRun += 1
		else:
			break
	
	return blockRun

def searchRight(imageFile, entropyLimit, currentPosition, imageSize, blockSize):
	""" Return the run of contiguous blocks to the right in imageFile 
		over entropyLimit, starting at currentPosition.
	"""
	blockRun = 0
	
	while (currentPosition+1)*blockSize < imageSize:
		
		currentPosition += 1
		
		imageFile.seek(currentPosition*blockSize)
		block = imageFile.read(blockSize)
		
		if entropy(block) > entropyLimit:
			blockRun += 1
		else:
			break
	
	return blockRun


def searchImage(imageName, minContainerSize, offset, length, entropyLimit, blockSize):
	""" Search a .dd binary image for blocks of text over the specified
		entropy limit and larger than minContainerSize.
	"""
	
	f = open(imageName, 'rb')
	currentPosition = minContainerSize/blockSize - 2 + offset
	imageSize = os.path.getsize(imageName)
	
	if length != 0:
		imageSize = (offset + length) * blockSize
	
	print "\nSearching for contiguous block runs in "\
			+ imageName + "\nwith options: "\
			+" \n\tentropy limit: " + str(entropyLimit)\
			+ "\n\tminimum container size (bytes): " + str(minContainerSize)\
			+ "\n\tblock size (bytes): " + str(blockSize)\
			+ "\n\toffset (blocks): " + str(offset)\
			+ "\n\tlength after offset (blocks): " + str(imageSize/blockSize) + "\n"
	
	print "Potential TrueCrypt containers (units in blocks):\n"
	
	t1=datetime.now()
	
	while currentPosition*blockSize < imageSize:
		
		increment = minContainerSize/blockSize

		f.seek(currentPosition*blockSize)
		block = f.read(blockSize)
		
		if entropy(block) > entropyLimit:
			leftRun = searchLeft(f, entropyLimit, currentPosition, blockSize)
			rightRun = searchRight(f, entropyLimit, currentPosition, imageSize, blockSize)

			if (leftRun + rightRun + 1)*blockSize >= minContainerSize:
				print "\tstart:"+str(currentPosition-leftRun) + ", " + "len:"+str((leftRun + rightRun + 1))
				if minContainerSize < rightRun*blockSize:
					# skip the size of the right run, otherwise we might get the
					# same block again the next interation
					increment = rightRun+1
		
		currentPosition += increment

		
	print "\ntotal time: " + str(datetime.now()-t1) + "\n"

def searchFile(fileName, minContainerSize, entropyLimit, blockSize):
	""" Searche takes an individual file and checks its entropy """

	fileSize = os.path.getsize(fileName)
	if fileSize >= minContainerSize and fileSize >= blockSize and (fileSize % 512) == 0:
		f=open(fileName, 'rb')
		block = f.read(blockSize)
		if not commonHeader(block):
			currentPosition = 1
			while (currentPosition)*blockSize < fileSize:
				f.seek(currentPosition*blockSize)
				block = f.read(blockSize)
		
				if entropy(block) < entropyLimit:
					f.close()
					return False
				currentPosition += 1
			f.close()
			return True
	else:
		return False

def searchDir(dirName, minContainerSize, entropyLimit, blockSize):
	""" Searches recursively a directory for truecrypt container files """

	print "\nSearching for TrueCrypt containers in:\n"\
			+ os.path.realpath(dirName) + "\nwith options: "\
			+" \n\tentropy limit: " + str(entropyLimit)\
			+ "\n\tminimum container size (bytes): " + str(minContainerSize)\
			+ "\n\tblock size (bytes): " + str(blockSize) + "\n"
	
	print "Potential TrueCrypt containers:\n"
	for root, subFolders, files in os.walk(dirName):
		for filename in files:
			fileName=os.path.realpath(os.path.join(root,filename))
			if searchFile(fileName, minContainerSize, entropyLimit, blockSize):
				print "\t", fileName

def usage():
	print "\nTCDiscover: A program to hunt for Truecrypt containers in a .DD drive image or a directory."
	print "\nUsage: ./tcdiscover.py -i <image file>"
	print "\nUsage: ./tcdiscover.py -d <directory>"
	print "\noptional flags:\n\t-e <entropy limit>"
	print "\t-s <minimum container size in bytes>"
	print "\t-b <block size>"
	print "\t-c <scalpel config file of common file headers>"
	print "\t-o <offset in blocks into image file to start searchs>"
	print "\t-l <length in blocks after offset to end search>\n"

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:c:e:s:d:o:l:", ["help"])
	except getopt.GetoptError, err:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)

	imageName = ""
	directory = ""
	configFile = ""
	entropyLimit = 7.0		
	minContainerSize = 4194304
	offset = 0
	length = 0
	blockSize = 512

	for o, a in opts:
		if o == "-c":
			configFile = a
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o in "-e":
			entropyLimit = float(a)
		elif o in "-i":
			imageName = a
		elif o in "-s":
			minContainerSize = int(a)
		elif o in "-d":
			directory = a
		elif o in "-o":
			offset = int(a)
		elif o in "-l":
			length = int(a)
		elif o in "-b":
			blockSize = int(a)
		else:
			assert False, "unhandled option"
	
	if imageName == "" and directory == "":
		usage()
		sys.exit()
	
	initializeHeaders(configFile)
	if (imageName != ""):
		searchImage(imageName, minContainerSize, offset, length, entropyLimit, blockSize)
	elif (directory != ""):
		searchDir(directory, minContainerSize, entropyLimit, blockSize)
	else:
		print "No input selected! Exiting."

if __name__ == "__main__":
    main()
